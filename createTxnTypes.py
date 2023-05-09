

appendageParseFunctionDict = {0x000b : 4, 0x00fc: 4, 0x0102: 7}


def main():

	with open("txtypes.txt", "r") as f:

		out = '//This is an auto generated file by createTxnTypes.py\n\n#include <stdint.h>\n#include "ardor.h"\n\nconst txnType TXN_TYPES[] = {'

		lines = f.readlines()

		for line in lines:
			txtype, txSubType, name = line.split(',')

			txtype = int(txtype) & 0xFF
			txSubType = int(txSubType) & 0xFF

			parseFunction = appendageParseFunctionDict.get(txSubType * 256 + txtype , 0)

			out += '{' + '0x{:02x}{:02x},"{}",{}'.format(txSubType, txtype, name.rstrip(), parseFunction) + '},\n'


		print(out[0:-2] + "};")

	print("\nconst uint8_t LEN_TXN_TYPES = {};".format(len(lines)))

if __name__ == "__main__":
	main()