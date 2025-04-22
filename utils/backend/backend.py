#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Author: www
@Date: 2024/6/26 下午2:17
@Description: 
"""
import contextlib
import io
import json
import ssl
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from typing import List, Union, Tuple
from urllib.parse import urlparse

import aiohttp
from aiohttp import WSMsgType, ClientConnectorError, ClientWebSocketResponse, WSCloseCode, WSServerHandshakeError
from async_timeout import timeout
from loguru import logger
from pyrogram import Client
from pyrogram.enums import ParseMode
from pyrogram.errors import MessageNotModified, RPCError, PhotoInvalidDimensions
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton, InputMediaPhoto

from bot import check
from bot.config import lang, CONFIG
from bot.init import app as gapp
from bot.queue import message_edit_queue as meq, message_delete_queue as mdq
from bot.api import Api
from bot.utils import gen_key, parse_proxy
from bot.callbacks import KoiCallback
from utils import DEFAULT_UA
from utils.algorithm import hash_ms
from utils.cleaner import ResultCleaner
from utils.export import KoiDraw, TopoDraw
from utils.types.callback import KoiCallbackData
from utils.types.items import ScriptItem, BaseItem, ItemType, GEO_ITEMS
from utils.types.miaospeed import SlaveRequestMatrixEntry, SlaveRequestConfigs, SlaveRequestNode, SlaveRequestOptions, \
    SlaveEntrySlot
from utils.types.miaospeed import SlaveRequest as MSSlaveRequest
from utils.types.miaospeed import SlaveRequestMatrixType, SSLType, SlaveRequestBasics
from utils.types.miaospeed import Script as MSScript, ScriptType, MatrixResponse
from utils.types.task import SlaveRequest, SlaveRuntimeOption, OutputType, TaskResult
from utils.types.config import MiaoSpeedSlave, SpeedFormat, Slave
from utils.types.draw import DrawConfig
from utils.types.miaospeed import SlaveResponse

MS_BUILDTOKEN = "MIAOKO4|580JxAo049R|GEnERAl|1X571R930|T0kEN"  # miaospeed的build_token
MS_CONN = {}
CONNTESTIKM = InlineKeyboardMarkup(
    [
        [InlineKeyboardButton(lang.realtime, callback_data=Api.speed_realtime)],
        [InlineKeyboardButton(lang.task_stop_1, callback_data=Api.speed_stop)],
    ]
)
CONNTESTIKM2 = InlineKeyboardMarkup(
    [
        [InlineKeyboardButton(lang.realtime2, callback_data=Api.speed_realtime)],
        [InlineKeyboardButton(lang.task_stop_1, callback_data=Api.speed_stop)],
    ]
)
REALTIME_EXECUTER = ThreadPoolExecutor(thread_name_prefix='asyncio_realtime_executer')


class MiaoSpeed:
    def __init__(self,
                 slave_config: MiaoSpeedSlave = None,
                 slave_request: MSSlaveRequest = None,
                 proxyconfig: List[dict] = None,
                 debug: bool = False,
                 ):
        """
        初始化miaospeed
        :param slave_config 测速后端自定义配置
        :param slave_request: MS的请求结构体
        :param debug 是否是debug模式，会打印出多一点信息

        """
        self.scfg = slave_config
        self.proxy = None
        if self.scfg.proxy:
            pcfg = parse_proxy(self.scfg.proxy)
            if pcfg and pcfg.get("scheme", None) == "http":
                self.proxy = self.scfg.proxy
        self.buildtoken = slave_config.buildtoken or MS_BUILDTOKEN
        self.token = slave_config.token
        addr = slave_config.address if slave_config.address else ""
        i = addr.rfind(":")
        self.host = addr[:i]
        try:
            self.port = int(addr[i + 1:])
        except (TypeError, ValueError):
            raise ValueError(f"can not parse address: {addr}")
        self.path = "/" + slave_config.path.removeprefix("/") if slave_config.path else "/"
        if self.path == "/":
            logger.warning(lang.ws_info12 + self.path)

        self.nodes = proxyconfig or []
        if slave_config.tls is True:
            self.ssl_type = SSLType.SELF_SIGNED if slave_config.skipCertVerify is True else SSLType.SECURE
        else:
            self.ssl_type = SSLType.NONE
        self.ws_scheme, self.verify_ssl = self.get_ws_opt()
        self._debug = debug
        self.SlaveRequest = slave_request
        if self.nodes and not slave_request.Nodes:
            self.SlaveRequest.Nodes = [SlaveRequestNode(str(i), str(node)) for i, node in enumerate(self.nodes)]

        self.check_slave_request()
        self.tempinfo = {"节点名称": [], "类型": []}
        self.last_progress = 0
        self.realtime_flag = False
        self.realtime_flag2 = False

    def check_slave_request(self):
        if not self.SlaveRequest.Options.Matrices:
            raise ValueError(f"SlaveRequest.Options.Matrices is empty")
        # if not self.SlaveRequest.Nodes:
        #     raise ValueError(f"SlaveRequest.Nodes is empty")

    def hash_miaospeed(self, token: str, request: str):
        token = token or self.token
        request = request or self.SlaveRequest.to_json()
        return hash_ms(self.buildtoken, token, request)

    def sign_request(self):
        self.SlaveRequest.RandomSequence = "random"
        copysrt = deepcopy(self.SlaveRequest)  # 用深拷贝复制一份请求体数据，python拷贝行为涉及可变和不可变序列。
        copysrt.Challenge = ""  # 置为空是因为要与这个值进行比较，要是不为空，大概永远也过不了验证
        copysrt.Vendor = ""  # 因为miaospeed在这里拷贝的时候，并没有拷贝原来的Vendor值

        srt_json = copysrt.to_json()
        signed_req = self.hash_miaospeed(self.token, srt_json)
        self.SlaveRequest.Challenge = signed_req
        return signed_req

    def convert_matrices_pro(self, info: dict, matrices: List[MatrixResponse]):
        http_k = "HTTP?延迟"
        if self.SlaveRequest.Configs.PingAddress:
            parsed_url = urlparse(self.SlaveRequest.Configs.PingAddress)
            http_k = "HTTPS延迟" if parsed_url.scheme == "https" else "HTTP延迟"
        for m in matrices:
            if not m.Payload:
                continue
            j_obj: dict = json.loads(m.Payload)
            if not j_obj:
                continue
            if m.Type == SlaveRequestMatrixType.TEST_PING_CONN:
                if http_k not in info:
                    info[http_k] = []
                delay = j_obj.get('Value', 0)
                if delay and isinstance(delay, (int, float)):
                    info[http_k].append(delay)
                else:
                    info[http_k].append(0)
            elif m.Type == SlaveRequestMatrixType.TEST_PING_RTT:
                rtt_type = "TLS RTT" if "https" in self.SlaveRequest.Configs.PingAddress.lower() else "延迟RTT"
                if rtt_type not in info:
                    info[rtt_type] = []
                info[rtt_type].append(j_obj.get('Value', 0))
            elif m.Type == SlaveRequestMatrixType.TEST_SCRIPT:
                script_name = j_obj.get('Key', '')
                if script_name and (script_name != "HTTP(S)延迟" or script_name != "HTTP延迟"):
                    if script_name not in info:
                        info[script_name] = []
                    info[script_name].append(j_obj.get('Text', "N/A"))
            elif m.Type == SlaveRequestMatrixType.UDP_TYPE:
                if "UDP类型" not in info:
                    info["UDP类型"] = []
                info["UDP类型"].append(j_obj.get('Value', ""))
            elif m.Type == SlaveRequestMatrixType.SPEED_AVERAGE:
                if "平均速度" not in info:
                    info["平均速度"] = []
                info["平均速度"].append(j_obj.get('Value', 0))
            elif m.Type == SlaveRequestMatrixType.SPEED_MAX:
                if "最大速度" not in info:
                    info["最大速度"] = []
                info["最大速度"].append(j_obj.get('Value', 0))
            elif m.Type == SlaveRequestMatrixType.SPEED_PER_SECOND:
                if "每秒速度" not in info:
                    info["每秒速度"] = []
                info["每秒速度"].append(j_obj.get('Speeds', []))
            elif m.Type == SlaveRequestMatrixType.TEST_PING_MAX_RTT:
                if "MAX RTT" not in info:
                    info["MAX RTT"] = []
                info["MAX RTT"].append(j_obj.get('Value', -1))
            elif m.Type == SlaveRequestMatrixType.TEST_PING_SD_RTT:
                if "RTT标准差" not in info:
                    info["RTT标准差"] = []
                info["RTT标准差"].append(j_obj.get('Value', -1))
            elif m.Type == SlaveRequestMatrixType.TEST_PING_SD_CONN:
                if "HTTP标准差" not in info:
                    info["HTTP标准差"] = []
                info["HTTP标准差"].append(j_obj.get('Value', -1))
            elif m.Type == SlaveRequestMatrixType.TEST_PING_TOTAL_RTT:
                if "总RTT" not in info:
                    info["总RTT"] = []
                d = j_obj.get('Values', [])
                if isinstance(d, list):
                    info["总RTT"].append(','.join(str(i) for i in d))
                else:
                    info["总RTT"].append("❌")
            elif m.Type == SlaveRequestMatrixType.TEST_PING_TOTAL_CONN:
                if "总HTTP" not in info:
                    info["总HTTP"] = []
                d = j_obj.get('Values', [])
                if isinstance(d, list):
                    info["总HTTP"].append(','.join(str(i) for i in d))
                else:
                    info["总HTTP"].append("❌")
            elif m.Type == SlaveRequestMatrixType.TEST_HTTP_CODE:
                if "HTTP状态码" not in info:
                    info["HTTP状态码"] = []
                d = j_obj.get('Values', [])
                if isinstance(d, list):
                    info["HTTP状态码"].append(','.join(str(i) for i in d))
                else:
                    info["HTTP状态码"].append("❌")
                info["HTTP状态码"].append(','.join(str(i) for i in j_obj.get('Values', [])))
            elif m.Type == SlaveRequestMatrixType.TEST_PING_PACKET_LOSS:
                if "丢包率" not in info:
                    info["丢包率"] = []
                info["丢包率"].append(j_obj.get('Value', -1))

    def convert_result(self, srp: SlaveResponse):
        info = {
            "节点名称": [],
            "类型": [],
        }
        sl_slot = srp.Result.Results

        # _resdata2 = _resdata.pop('Result', {}).pop('Results', [])

        def get_node_index(r: SlaveEntrySlot):
            return self.nodes.index(next(filter(lambda node: node['name'] == r.ProxyInfo.Name, self.nodes)))

        with contextlib.suppress(Exception):
            sl_slot: List[SlaveEntrySlot] = sorted(sl_slot, key=get_node_index, reverse=False)  # 按原始节点顺序排序

        for st in sl_slot:
            # 按行来填充数据
            proxyinfo = st.ProxyInfo
            info["节点名称"].append(proxyinfo.Name)
            info["类型"].append(proxyinfo.Type)
            self.convert_matrices_pro(info, st.Matrices)
        info['线程'] = self.SlaveRequest.Configs.DownloadThreading
        info["version"] = srp.MiaoSpeedVersion
        # print(info)
        return info

    def convert_progress(self, srp: SlaveResponse):
        self.tempinfo["节点名称"].append(srp.Progress.Record.ProxyInfo.Name)
        self.tempinfo["类型"].append(srp.Progress.Record.ProxyInfo.Type)
        if '线程' not in self.tempinfo:
            self.tempinfo['线程'] = self.SlaveRequest.Configs.DownloadThreading
        self.tempinfo["version"] = srp.MiaoSpeedVersion
        self.convert_matrices_pro(self.tempinfo, srp.Progress.Record.Matrices)

    def convert_with_georesult(self, _resdata: dict, slavereq_runtime: SlaveRuntimeOption):
        res = _resdata.pop('Result', {}).pop('Results', [])
        info = ResultCleaner.cleaning_geo(res, slavereq_runtime)
        info['线程'] = self.SlaveRequest.Configs.DownloadThreading
        info["version"] = _resdata.get("MiaoSpeedVersion", "")
        return info

    async def progress(self, ms_data: dict, slavereq: SlaveRequest):
        sres = SlaveResponse().from_obj(deepcopy(ms_data))
        if not sres.Result.Results and sres.Progress.Record.InvokeDuration:
            self.convert_progress(sres)
        botmsg = await gapp.get_messages(slavereq.task.botMsgChatID, slavereq.task.botMsgID)
        if slavereq.runtime.realtime is True:
            ikm = CONNTESTIKM2
        else:
            ikm = CONNTESTIKM
        if botmsg.reply_markup:
            if "✅" in botmsg.reply_markup.inline_keyboard[0][0].text:
                if len(self.nodes) <= 40:
                    ikm = CONNTESTIKM2
                    self.realtime_flag = True
                    await realtime(gapp, self, slavereq)
                else:
                    logger.info("实时渲染不支持节点数超过40个")
                    self.realtime_flag = False
                    ikm = CONNTESTIKM
            else:
                self.realtime_flag = False
                ikm = CONNTESTIKM
        if self.realtime_flag is False:
            await self._progress(sres, slavereq, ikm)

    async def handle_conn(self, ws: ClientWebSocketResponse, slavereq: SlaveRequest):
        resdata = {}
        while True:
            msg = await ws.receive()
            if self._debug:
                print(msg.data)
            if msg.type in (aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.ERROR):
                logger.info("websocket connection closed")
                put_opt = (slavereq.task.botMsgChatID, slavereq.task.botMsgID, lang.ws_conn_err6)
                meq.put(put_opt + (5,))
                break
            elif msg.type == WSMsgType.TEXT:
                ms_data: dict = json.loads(msg.data)
                if not ms_data:
                    continue
                if 'Result' in ms_data and ms_data.get('Result', {}):
                    if slavereq.contain_geo():
                        resdata = self.convert_with_georesult(ms_data, slavereq.runtime)
                    else:
                        sres = SlaveResponse().from_obj(deepcopy(ms_data))
                        resdata = self.convert_result(sres)
                    break
                elif 'Error' in ms_data and ms_data.get('Error', ''):
                    error_text = f"{lang.error} {ms_data.get('Error', '')}"
                    resdata.clear()
                    resdata['error'] = error_text
                    break
                elif 'Progress' in ms_data and ms_data.get('Progress', {}):
                    await self.progress(ms_data, slavereq)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                pass
        return resdata

    async def start(self, slavereq: SlaveRequest = None):
        err_text = ""
        conn_key = str(slavereq.task.botMsgChatID) + ":" + str(slavereq.task.botMsgID)
        task_res = TaskResult()
        task_res.startTime = time.time()
        ws_scheme, verify_ssl = self.get_ws_opt()
        if len(MS_CONN) > 100:  # 清理占用
            logger.warning("WebSocket连接资源已超过100条，请联系开发者优化。")

        async with aiohttp.ClientSession() as session:
            # resdata = {}
            try:
                async with session.ws_connect(f"{ws_scheme}://{self.host}:{self.port}{self.path}",
                                              verify_ssl=verify_ssl,
                                              headers={"User-Agent": DEFAULT_UA},
                                              proxy=self.proxy) as ws:
                    self.sign_request()  # 签名请求
                    self.last_progress = time.time()
                    if conn_key not in MS_CONN:
                        MS_CONN[conn_key] = ws
                    await ws.send_str(self.SlaveRequest.to_json())
                    logger.info(lang.ws_info11)
                    task_res.data = await self.handle_conn(ws, slavereq)
                    # task done
                    await ws.close(code=aiohttp.WSCloseCode.GOING_AWAY,
                                   message=b'(EOF)The connection is closed by the peer.')
            except WSServerHandshakeError as e:
                logger.error(str(e))
                err_text = f"{lang.error} {e.message} {e.status}"
            except ClientConnectorError as e:
                logger.error(str(e))
                err_text = lang.ws_conn_err2 + lang.ws_conn_err7 + slavereq.slave.comment
            except asyncio.TimeoutError:
                err_text = f"{lang.ws_conn_err4}{self.port}"
                logger.warning(err_text)
            except Exception as e:
                logger.exception(str(e))
                logger.error(str(e))
            finally:
                task_res.endTime = time.time()
                task_res.timeUsed = task_res.endTime - task_res.startTime
                if conn_key in MS_CONN:
                    conn: ClientWebSocketResponse = MS_CONN.pop(conn_key)
                    await conn.close()
                if "error" in task_res.data and task_res.data['error']:
                    err_text = task_res.data['error']
                if err_text:
                    put_opt = (slavereq.task.botMsgChatID, slavereq.task.botMsgID, err_text, 5)
                    meq.put(put_opt)
                return task_res

    async def _progress(self, srp: SlaveResponse, slavereq: SlaveRequest = None, ikm: InlineKeyboardMarkup = None):
        time1 = self.last_progress
        count = len(self.tempinfo['节点名称'])
        queuing = srp.Progress.Queuing
        is_speed = any("SPEED" in i.name for i in slavereq.items)
        is_geo = any("GEOIP" in i.name for i in slavereq.items)
        cidx = 1 if is_speed else 2 if is_geo else 3
        scomment = slavereq.slave.comment
        t2 = time.time()
        if 0 <= count <= 1 or count == len(self.nodes) or (count % 4 == 0 and t2 - time1 > 4):
            self.last_progress = t2

            progress_text = ms_progress_text(cidx, count, len(self.nodes), queuing,
                                             scomment)
            # if len(self.nodes) > 20:
            #     progress_text += lang.ws_conn_msg
            p_opt = (slavereq.task.botMsgChatID, slavereq.task.botMsgID, progress_text, 5, ikm)
            meq.put(p_opt)

    def get_ws_opt(self) -> Tuple[str, bool]:
        if self.ssl_type == SSLType.SECURE:
            ssl_context = ssl.create_default_context()
            verify_ssl = True
        elif self.ssl_type == SSLType.SELF_SIGNED:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            verify_ssl = False
        elif self.ssl_type == SSLType.NONE:
            ssl_context = None
            verify_ssl = None
        else:
            raise ValueError(f"{lang.ms_type_err2} {type(self.ssl_type).__name__}:{self.ssl_type}")
        ws_scheme = "ws" if ssl_context is None else "wss"
        return ws_scheme, verify_ssl

    async def ping(self, session: aiohttp.ClientSession):
        ws_scheme, verify_ssl = self.get_ws_opt()
        try:
            async with session.ws_connect(f"{ws_scheme}://{self.host}:{self.port}{self.path}",
                                          verify_ssl=verify_ssl,
                                          proxy=self.proxy,
                                          headers={"User-Agent": DEFAULT_UA}) as ws:
                self.sign_request()  # 签名请求
                t1 = time.time()
                await ws.send_str(self.SlaveRequest.to_json())
                while True:
                    msg = await ws.receive()
                    if msg.type in (aiohttp.WSMsgType.CLOSED,
                                    aiohttp.WSMsgType.ERROR):
                        return 0
                    elif msg.type == WSMsgType.TEXT:
                        return int((time.time() - t1) * 1000)
                    else:
                        return 0
        except (ClientConnectorError, asyncio.TimeoutError):
            return 0
        except Exception as e:
            logger.error(str(e))
            return 0

    @staticmethod
    async def stop(conn_key: str) -> str:
        if conn_key in MS_CONN:
            ws_conn = MS_CONN.get(conn_key, None)
            if isinstance(ws_conn, ClientWebSocketResponse):
                try:
                    MS_CONN.pop(conn_key, None)
                    await ws_conn.close(code=WSCloseCode.GOING_AWAY)
                    return ""
                except Exception as e:
                    logger.warning(str(e))
                    return str(e)
            return ""
        else:
            return lang.ws_conn_err

    @staticmethod
    async def isalive(slave: Slave, session: aiohttp.ClientSession = None) -> bool:
        """
        检查此后端是否存活
        """
        session = session or aiohttp.ClientSession()
        try:
            if slave.type == "miaospeed":
                srme_list = [SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_CONN, "")]
                slopt = SlaveRequestOptions(Matrices=srme_list)
                msreq = MSSlaveRequest(Options=slopt)
                try:
                    if not isinstance(slave, MiaoSpeedSlave):
                        raise TypeError(f"{slave.__class__.__name__} is not a MiaoSpeedSlave. ")
                    ms = MiaoSpeed(slave, msreq, [])
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    return False
                ms.SlaveRequest.Basics.Invoker = slave.invoker or ""
                async with timeout(30):
                    res = await ms.ping(session)
                    return bool(res)
        except (asyncio.exceptions.TimeoutError, aiohttp.WSServerHandshakeError, ClientConnectorError):
            return False
        except Exception as e:
            logger.error(e)
            return False


def ms_progress_text(corelabel: Union[int, str], current: int, total: int, queuing: int, scomment: str = "Local"):
    if corelabel == 'SpeedCore' or corelabel == 1:
        testtext = lang.progress_1
    elif corelabel == 'TopoCore' or corelabel == 2:
        testtext = lang.progress_2
    elif corelabel == 'ScriptCore' or corelabel == 3:
        testtext = lang.progress_3
    else:
        testtext = "未知测试进行中"
    progress_bars = lang.KoiConfig_bot_bar
    bracketsleft = lang.KoiConfig_bot_bleft
    bracketsright = lang.KoiConfig_bot_bright
    bracketsspace = lang.KoiConfig_bot_bspace

    pc = current / total * 100
    p_text = "%.2f" % pc
    equal_signs = int(pc / 5)
    space_count = 20 - equal_signs
    progress_bar = f"{bracketsleft}" + f"{progress_bars}" * equal_signs + \
                   f"{bracketsspace}" * space_count + f"{bracketsright}"
    if queuing > 0:
        edit_text = (f"{lang.progress_4}{scomment}\n{testtext}\n{lang.progress_5} `{queuing}`\n\n" + progress_bar +
                     f"\n\n{lang.progress_6}\n" + p_text + "%     [" + str(current) + "/" + str(total) + "]")
    else:
        edit_text = f"{lang.progress_4}{scomment}\n{testtext}\n\n" + progress_bar + f"\n\n{lang.progress_6}\n" + \
                    p_text + "%     [" + str(current) + "/" + str(total) + "]"
    return edit_text


def build_req_matrix(items: List[ItemType] = None) -> List[SlaveRequestMatrixEntry]:
    if items is None or not isinstance(items[0], (BaseItem, ScriptItem)):
        return []
    srme_list = []
    for i in items:
        if i.name == "TEST_SCRIPT":
            srme_list.append(
                SlaveRequestMatrixEntry(
                    Type=SlaveRequestMatrixType.TEST_SCRIPT,
                    Params=i.script.name
                )
            )
        elif i.name == "TEST_PING_RTT":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_RTT, ""))
        elif i.name == "TEST_PING_MAX_RTT":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_MAX_RTT, ""))
        elif i.name == "TEST_PING_SD_RTT":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_SD_RTT, ""))
        elif i.name == "TEST_PING_SD_CONN":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_SD_CONN, ""))
        elif i.name == "TEST_PING_CONN":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_CONN, ""))
        elif i.name == "TEST_HTTP_CODE":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_HTTP_CODE, ""))
        elif i.name == "TEST_PING_TOTAL_CONN":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_TOTAL_CONN, ""))
        elif i.name == "TEST_PING_TOTAL_RTT":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_TOTAL_RTT, ""))
        elif i.name == "SPEED_AVERAGE":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.SPEED_AVERAGE, "0"))
        elif i.name == "SPEED_MAX":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.SPEED_MAX, "0"))
        elif i.name == "SPEED_PER_SECOND":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.SPEED_PER_SECOND, "0"))
        elif i.name == "UDP_TYPE":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.UDP_TYPE, "0"))
        elif i.name == "GEOIP_INBOUND":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.GEOIP_INBOUND, i.script.name))
        elif i.name == "GEOIP_OUTBOUND":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.GEOIP_OUTBOUND, i.script.name))
        elif i.name == "TEST_PING_PACKET_LOSS":
            srme_list.append(SlaveRequestMatrixEntry(SlaveRequestMatrixType.TEST_PING_PACKET_LOSS, ""))
    return srme_list


async def miaospeed_client(app: Client, slavereq: SlaveRequest):
    msg = await app.get_messages(slavereq.task.chatID, slavereq.task.messageID)
    if not isinstance(slavereq.slave, MiaoSpeedSlave):
        raise TypeError(lang.ms_type_err)

    if not isinstance(app, Client):
        logger.warning("Failed to get Bot client instance, will not be able to generate and send images.")
        return
    if slavereq.slave.path is None or not isinstance(slavereq.slave.path, str):
        slavereq.slave.path = "/"
    koi_callback = KoiCallback(CONFIG.safe_copy(), lang)
    if not await koi_callback.on_presend(msg, slavereq):
        return
    if slavereq.runtime.ipstack is None:
        slavereq.runtime.ipstack = CONFIG.runtime.ipstack
    if slavereq.runtime.entrance is None:
        slavereq.runtime.entrance = CONFIG.runtime.entrance
    if slavereq.runtime.output is None:
        slavereq.runtime.output = OutputType.IMAGE
    if not slavereq.runtime.speedFiles:
        slavereq.runtime.speedFiles = CONFIG.runtime.speedFiles
    try:
        srcfg = SlaveRequestConfigs.from_option(slavereq.slave.option).merge_runtime(slavereq.runtime).check()
    except ValueError as e:
        logger.exception(e)
        return
    slopt = SlaveRequestOptions(Matrices=build_req_matrix(slavereq.items))
    msreq = MSSlaveRequest(
        SlaveRequestBasics(
            ID=slavereq.task.site,
            Slave=str(slavereq.slave.id),
            SlaveName=slavereq.slave.comment,
            Invoker=str(slavereq.slave.invoker) or str(app.me.id),
            Version=app.app_version
        ),
        slopt,
        srcfg
    )
    for item in slavereq.items:
        if item.script and item.script.content:
            if item.script.name in GEO_ITEMS:
                msreq.Configs.Scripts.append(MSScript(ID=item.script.name, Type=ScriptType.STypeIP.value,
                                                      Content=item.script.content))
            else:
                msreq.Configs.Scripts.append(MSScript(ID=item.script.name, Content=item.script.content))
    # debug
    if slavereq.contain_speed():
        logger.debug(f"Speed test DownloadURL: {msreq.Configs.DownloadURL}")
    ms = MiaoSpeed(slavereq.slave, msreq, slavereq.proxies)

    try:
        logger.info(f"{lang.ws_info14} {slavereq.task.site} | "
                    f"{slavereq.slave.comment} | "
                    f"{len(slavereq.proxies)}{lang.ws_info16}")
        task_res = await ms.start(slavereq)
        result2 = await koi_callback.on_result(msg, slavereq, task_res.data)
        if isinstance(result2, KoiCallbackData):
            task_res.data.update(result2.result)
        if 'error' in task_res.data:
            return
        task_res.data = (ResultCleaner(task_res.data, SpeedFormat.from_str(CONFIG.image.speedFormat),
                                       CONFIG.detectInvalidResults, srcfg.PingAddress).start(slavereq.runtime.sort))
        if isinstance(task_res, TaskResult) and task_res:
            logger.info(f"{slavereq.task.name} {lang.ws_info15}")
            await push_results(app, slavereq, task_res, srcfg)
        elif isinstance(task_res, str):
            pass
    except Exception as e:
        await app.send_message(slavereq.task.chatID, lang.error + f" `{str(e)}`", parse_mode=ParseMode.MARKDOWN)
        logger.exception(e)
        return


async def push_results(app: Client, slavereq: SlaveRequest, result: TaskResult, srcfg: SlaveRequestConfigs):
    msg = await app.get_messages(slavereq.task.chatID, slavereq.task.messageID)
    botmsg = await app.get_messages(slavereq.task.chatID, slavereq.task.botMsgID)
    s3 = int(result.timeUsed)
    loop = asyncio.get_running_loop()
    cfg = DrawConfig(slavereq=slavereq, sort=slavereq.runtime.sort, timeused=f"{int(s3)}", )
    cfg.image = CONFIG.image
    # if cfg.slavereq.runtime.pingURL is None:
    #     cfg.slavereq.runtime.pingURL = srcfg.PingAddress  # 如果不覆写，会报错
    cfg.threadNum = srcfg.DownloadThreading
    cfg.timeused = f"{int(s3)}"
    cfg.trafficused = result.data.get("消耗流量", 0)
    cfg.filter.include = slavereq.runtime.includeFilter
    cfg.filter.exclude = slavereq.runtime.excludeFilter
    cfg.slaveVersion = result.data.get("version", "")
    if slavereq.runtime.output is None or slavereq.runtime.output == OutputType.IMAGE:
        if slavereq.contain_geo():
            cfg.noUnlockedStats = True
            kd = TopoDraw(cfg, result.data["inbound"], result.data["outbound"])
        else:
            if not slavereq.contain_speed():
                cfg.noUnlockedStats = True
            kd = KoiDraw('节点名称', result.data, cfg)
        try:
            file_name, img_size = await loop.run_in_executor(REALTIME_EXECUTER, kd.draw)
            t_time = int(time.time() - slavereq.task.createTime)
            await check.check_photo(app, msg, botmsg, file_name, s3, img_size, t_time)
            if not CONFIG.image.save:
                Path(file_name).unlink(missing_ok=True)
            else:
                print(f"Image output: {file_name}")
        except Exception as e:
            logger.exception(e)
            await msg.reply(lang.error + f" `{str(e)}`", parse_mode=ParseMode.MARKDOWN)
    elif slavereq.runtime.output == OutputType.JSON:
        file_name = f"{time.strftime('%Y%m%d%H%M%S')}-{slavereq.task.site}-{slavereq.task.name}.json"
        await check.check_json(app, msg, botmsg, file_name, cfg.timeused, result.data)


async def realtime(app: Client, ms: MiaoSpeed, slavereq: SlaveRequest):
    loop = asyncio.get_running_loop()
    s2 = time.time() - slavereq.task.createTime
    cfg = DrawConfig()
    srcfg = ms.SlaveRequest.Configs
    cfg.image = CONFIG.image
    cfg.slavereq = slavereq
    cfg.sort = slavereq.runtime.sort
    cfg.threadNum = srcfg.DownloadThreading
    cfg.timeused = f"{s2:.1f}"
    pers = ms.tempinfo.get("每秒速度", [])
    if pers and isinstance(pers, list):
        for p in pers:
            try:
                cfg.trafficused += sum(p)
            except (ValueError, TypeError):
                pass
    cfg.filter.include = slavereq.runtime.includeFilter
    cfg.filter.exclude = slavereq.runtime.excludeFilter
    cfg.slaveVersion = ms.tempinfo.get("version", "")
    botmsg = await app.get_messages(slavereq.task.botMsgChatID, slavereq.task.botMsgID)
    # print(ms.tempinfo)
    result = deepcopy(ms.tempinfo)
    try:
        sf = SpeedFormat(CONFIG.image.speedFormat)
    except ValueError:
        sf = SpeedFormat.BYTE_DECIMAL
    result = ResultCleaner(result, sf, CONFIG.detectInvalidResults, srcfg.PingAddress).start(slavereq.runtime.sort)
    if slavereq.runtime.output == OutputType.IMAGE and slavereq.contain_speed():
        kd = KoiDraw('节点名称', result, cfg)
        writeable = io.BytesIO()
        _, img_size = await loop.run_in_executor(REALTIME_EXECUTER, kd.draw, False, False, writeable)

        ikm = CONNTESTIKM2 if botmsg.reply_markup and "✅" in botmsg.reply_markup.inline_keyboard[0][0].text else \
            CONNTESTIKM
        if len(ms.nodes) > 40:
            b2 = await botmsg.reply(lang.realtime4, quote=True)
            mdq.put(b2, revoke=True)
            return
        is_ok = False
        x, y = img_size if img_size is not None else (0, 0)
        if x > 0 and y > 0:
            if x < 3500 and y < 3500:
                is_ok = True
        if is_ok is False and not ms.realtime_flag2:
            await botmsg.reply(lang.realtime5, quote=True)
            ms.realtime_flag2 = True
        try:
            if not botmsg.photo:
                b2 = await app.send_photo(slavereq.task.chatID, writeable, reply_markup=ikm,
                                          reply_to_message_id=slavereq.task.messageID)
                await botmsg.delete(revoke=True)
                slavereq.task.botMsgID = b2.id
                slavereq.task.botMsgChatID = b2.chat.id
                conn = MS_CONN.pop(gen_key(botmsg), None)
                MS_CONN[gen_key(b2)] = conn
                botmsg = b2
            if botmsg:
                await botmsg.edit_media(media=InputMediaPhoto(writeable, caption=botmsg.caption), reply_markup=ikm)
        except (MessageNotModified, PhotoInvalidDimensions):
            pass
        except RPCError as e:
            logger.exception(e)
            await botmsg.reply(f"{lang.error}{e.MESSAGE}")


if __name__ == '__main__':
    pass
