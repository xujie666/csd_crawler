import asyncio
import httpx
from hashlib import sha256
import hmac, base64
import random
from urllib.parse import urlparse
import json
import m3u8
from Crypto.Cipher import AES
# product by shenb
import os
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class CSDNClassRequest():

    def __init__(self, key, appsecret, headers=None):

        self.key = key
        self.appsecret = appsecret
        self.session = httpx.AsyncClient()
        self.headers = headers if headers is not None else {
            'accept': 'application/json, text/plain, */*',
            'origin': 'https://download.csdn.net',
            'referer': 'https://download.csdn.net/learn/37437/581622?spm=1003.2001.3001.4157',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36 Edg/103.0.1264.44',
            'cookie':''; 
            'X-Ca-Signature-Headers': 'x-ca-key,x-ca-nonce',
           'X-Ca-Signature': '',
           'X-Ca-Nonce': '',
           'X-Ca-Key': '',
            'Sec-Ch-Ua-Platform': 'windows'
        }

    def uuid(self):
        original_string = 'xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx'
        return ''.join(list(map(lambda x: hex(random.randint(1,17))[-1] if x == 'x' else x, original_string)))

    def sha256(self, data, key):
        key = key.encode('utf-8')       # sha256加密的key
        message = data.encode('utf-8')  # 待sha256加密的内容
        sign = base64.b64encode(hmac.new(key, message, digestmod=sha256).digest()).decode()
        return sign

    async def request(self, url, method='get', accept=None, contentType=None, date=None, data=None):

        parsed_url = urlparse(url)
        param = parsed_url[2] + '?' + parsed_url[4]
        method = method.upper()
        accept = accept if accept is not None else 'application/json, text/plain, */*'
        x_ca_key = self.key
        self.headers['X-Ca-Key'] = x_ca_key
        self.headers['accept'] = accept
        x_ca_nonce = self.uuid()
        self.headers['X-Ca-Nonce'] = x_ca_nonce

        encrypt_data = method + '\n' + accept + '\n\n\n\n' + 'x-ca-key:' + x_ca_key + '\n' + 'x-ca-nonce:' + x_ca_nonce + '\n' + param

        x_ca_signature = self.sha256(encrypt_data, self.appsecret)
        self.headers['X-Ca-Signature'] = x_ca_signature
        result = None
        while result is None:
            try:
                result = await self.session.request(url=url, method=method, headers=self.headers)
            except Exception as e:
                await asyncio.sleep(5)

        return result

session = CSDNClassRequest('20366374', '0zNRQvFxZoL4N9Y2uPDsoe4')

class CSDNCourseDownloader:
    global session

    def __init__(self, class_id):
        self.course_id = class_id
        self.class_entry_url = f'https://edu-core-api.csdn.net/web/lesson/playInfo?courseId={class_id}'

    async def download(self):
        resp = await session.request(self.class_entry_url) # 得到课程对应的课程内容
        # print(resp.text)
        json_data = json.loads(resp.text)

        course_info = json_data['data']['course_info']

        course_name = course_info['course_name'].replace('/', '_')
        if not (os.path.exists(course_name) and os.path.isdir(course_name)):
            os.mkdir(course_name)
        lesson_list = json_data['data']['directory']['lesson_list']
        lesson_info_list = []
        for lesson_list_key in lesson_list.keys():
            lesson_info_list.extend(lesson_list[lesson_list_key])

        tasks = []
        for index, lesson_info in enumerate(lesson_info_list):
            lesson_id = lesson_info['lesson_id']
            lesson_title = lesson_info['lesson_title']
            task = asyncio.create_task(CSDNLessonDownloader(self.course_id, lesson_id, lesson_title, course_name, (index + 1)).download())
            tasks.append(task)

        await asyncio.gather(*tasks)




class CSDNLessonDownloader:
    global session

    def __init__(self, course_id, lesson_id, lesson_title, course_name, course_index):
        self.course_id = course_id
        self.lesson_id = lesson_id
        self.lesson_title = lesson_title
        self.save_folder = course_name
        self.course_index = str(course_index)

    async def download(self):
        self.file_path = self.save_folder + '/' + self.course_index + '.' + self.lesson_title.replace('/','_') + '.mp4'
        if os.path.exists(self.file_path) :
            return

        info_url = f"https://bizapi.csdn.net/edu-academy-web/v1/material/info?cId={self.course_id}&courseId={self.course_id}&isFree=2&isMember=2&materialId={self.lesson_id}&playerVersion=2"
        resp = await session.request(info_url)
        json_data = json.loads(resp.text)
        m3u8_url = json_data['data']['info']['playUrl']
        m3u8_info = (await asyncio.create_task(session.request(m3u8_url))).text
        # print(m3u8_info)
        m3u8_parse = M3u8Parser(m3u8_info, m3u8_url)
        self.key = await m3u8_parse.get_key()
        if self.key == b'':
            return #下轮再来

        tasks = []

        for index, m3u8_file_url in enumerate(m3u8_parse.files_url):
            arr = [0 for i in range(15)]
            arr.append(index)
            task = asyncio.create_task(self.download_ts(self.save_folder, m3u8_file_url, bytearray(arr)))
            tasks.append(task)



        await asyncio.gather(*tasks)
        #完成后拼组文件
        with open(self.file_path, 'wb') as file:
            for m3u8_file_url in m3u8_parse.files_url:
                ts_file_name = m3u8_file_url.split('/')[-1]
                ts_path = self.save_folder + '/' + ts_file_name
                print('读入', ts_file_name)
                with open(ts_path, 'rb') as temp_file:
                    print('写入', self.file_path)
                    file.write(temp_file.read())
                os.remove(ts_path)

    async def download_ts(self, folder, url, iv):
        ts_file_name = url.split('/')[-1]
        ts_path = folder + '/' + ts_file_name
        if os.path.exists(ts_path) and os.stat(ts_path).st_size != 0:
            print(ts_file_name,'已下载: skip()',)
            return
        else:
            resp = await session.request(url)
            binary_data = resp.content
            decrypt_data = self.AES_Decrypt(binary_data, self.key, iv)
            with open(ts_path, 'wb') as file:
                file.write(decrypt_data)
            print(ts_file_name, '下载完成')
        # print(self.course_id, self.lesson_title)
        # for m3u8_file in m3u8_parse.files_url:
        #
x

    def AES_Decrypt(self, data, key, vi):
        cipher = AES.new(key, AES.MODE_CBC, vi)
        text_decrypted = cipher.decrypt(data)
        # 去补位
        text_decrypted = unpad(text_decrypted)
        return text_decrypted

class M3u8Parser:
    global session
    def __init__(self, content, origin_url):
        self.parse_url = urlparse(origin_url)
        self.pre_url = f'https://{self.parse_url.hostname}/' + self.parse_url.path.split('/')[1] + '/'
        self.m3u8_parsed_raw = m3u8.loads(content)
        self.files_url = self.m3u8_parsed_raw.files[1:] #除去key
        self.files_url = [self.pre_url + file_url for file_url in self.files_url]

    async def get_key(self):
        return (await asyncio.create_task(session.request(self.m3u8_parsed_raw.keys[0].absolute_uri))).content

async def main():
    lesson_id_list = [32772]
    tasks = []
    for lesson_id in lesson_id_list:

        task = asyncio.create_task(CSDNCourseDownloader(lesson_id).download())
        tasks.append(task)

    await asyncio.gather(*tasks)


asyncio.run(main())
