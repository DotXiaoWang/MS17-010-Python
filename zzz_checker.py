#!/usr/bin/python
# -*- encoding: utf-8 -*- 

from impacket import smb, smbconnection, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from struct import pack
import argparse, sys

from netaddr import IPNetwork

sys.path.insert(0, 'lib/')
import logger, banner
from mysmb import MYSMB

parser = argparse.ArgumentParser(description="MS17-010 Checker")
parser.add_argument("-t","--targets", metavar="",required=True, help="Target(s) to attack")
parser.add_argument("-c","--credentials", metavar="", help="Credentials to use")
args = parser.parse_args()

vulnerable = {}

if args.credentials:
	USERNAME=args.credentials[0]
	PASSWORD=args.credentials[1:]
else:
	USERNAME=''
	PASSWORD=''

NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

MSRPC_UUID_BROWSER  = uuidtup_to_bin(('6BFFD098-A112-3610-9833-012892020162','0.0'))
MSRPC_UUID_SPOOLSS  = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB','1.0'))
MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))
MSRPC_UUID_LSARPC   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))
MSRPC_UUID_SAMR     = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC','1.0'))

pipes = {
	'browser'  : MSRPC_UUID_BROWSER,
	'spoolss'  : MSRPC_UUID_SPOOLSS,
	'netlogon' : MSRPC_UUID_NETLOGON,
	'lsarpc'   : MSRPC_UUID_LSARPC,
	'samr'     : MSRPC_UUID_SAMR,
}

def get_targets(targets):
    # parses an input of targets to get a list of all possible ips
    target_list = []

    try:
        with open(targets, 'r') as file:
            contents = file.readlines()
            for i in (contents):
                target = i.rstrip()
                target_list.append(target)
            return target_list
    except:
        try:
            if "/" in targets:
                try:
                    subnet = IPNetwork(targets)
                except Exception as e:
                    logger.red('failed to parse:')
                    logger.red(str(e))
                    quit()

                for i in subnet:
                    tmp_str = str(i)
                    last_octet = str(tmp_str.split('.')[3])
                    if last_octet == '0' or last_octet == '255':
                        pass
                    else:
                        target_list.append(str(i))
                return target_list
            elif "," in targets:
                ips=targets.split(',')
                for ip in ips:
                    target_list.append(ip)
                return target_list

            else:
                target_list.append(targets)
                return target_list
        except Exception as e:
            logger.red('Failed to parse targets:')
            logger.red(str(e))
            quit()

def worawit(target):
	try:
		try:
			conn = MYSMB(target, timeout=5)
		except:
			logger.red('Unable to connect to [{}]'.format(logger.RED(target)))
			return False
		try:
			conn.login(USERNAME, PASSWORD)
		except:
			logger.red('Failed to authenticate to [{}]'.format(logger.RED(target)))
			return False
		finally:
			try:
				OS = conn.get_server_os()
			except Exception as e:
				logger.red(str(e))
				return False

		tid = conn.tree_connect_andx('\\\\' + target + '\\' + 'IPC$')
		conn.set_default_tid(tid)

		# test if target is vulnerable
		TRANS_PEEK_NMPIPE = 0x23
		recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
		status = recvPkt.getNTStatus()
		if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
			logger.green('[%s] VULNERABLE' % logger.GREEN(target))
			vulnerable[target]=[]
		else:
			logger.red('[%s] PATCHED' % logger.RED(target))

		pipes_found = []

		for pipe_name, pipe_uuid in pipes.items():
			try:
				dce = conn.get_dce_rpc(pipe_name)
				dce.connect()
				try:
					dce.bind(pipe_uuid, transfer_syntax=NDR64Syntax)
					try:
						pipes_found.append(pipe_name)
					except:
						pass
				except DCERPCException as e:
					if 'transfer_syntaxes_not_supported' in str(e):
						try:
							pipes_found.append(pipe_name)
						except:
							pass
					else:
						try:
							pipes_found.append(pipe_name)
						except:
							pass
				dce.disconnect()
				vulnerable[target]=pipes_found
			except smb.SessionError as e:
				continue
			except smbconnection.SessionError as e:
				continue

		conn.disconnect_tree(tid)
		conn.logoff()
		conn.get_socket().close()
	except KeyboardInterrupt:
		logger.red('Keyboard interrupt received..')
		quit()

def do_scan(targets):
	for target in targets:
		worawit(target)

banner.show('checker')
t=args.targets
targets=get_targets(t)

do_scan(targets)

logger.dump(vulnerable)
