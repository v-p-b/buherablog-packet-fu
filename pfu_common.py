import inspect

C_MOD = '\033[90m'
C_MSG = '\033[94m'
C_ERR = '\033[91m'
C_END = '\033[0m'

def msg(msg): pfu_out(msg, C_MSG)
def err(msg): pfu_out(msg, C_ERR)

def pfu_out(msg, msgcolor):
	mod = []
	for fr in reversed(inspect.stack()[1:-1]):
		mod.append(fr[3])
	print C_MOD+ '.'.join(mod) +' > '+ msgcolor + str(msg)+ C_END

