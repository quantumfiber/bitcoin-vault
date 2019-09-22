# -*- coding: utf-8 -*-


import bitcoinlib as btc
import os
import pickle
import datetime
import pprint
import codecs
import hashlib


NETWORK='testnet'



def revEndian(string):
    return ''.join(reversed([string[i:i+2] for i in range(0, len(string), 2)]))

def hashStr(bytebuffer):
    return str(codecs.encode(bytebuffer, 'hex'))[2:-1]

def doubleSha256(hex): 
    bin = codecs.decode(hex, 'hex')
    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()
    return revEndian(hashStr(hash2))

def txid(tx):
	return doubleSha256(tx.as_dict()['raw'] )


#%%

def create_seed_and_hdk(seed = None):	
	"""
	creates an hirachical determinsitic key
	"""
	# Generate a random Mnemonic HD Key
	#print("\nGenerate a random Mnemonic HD Key")
	entsize = 128
	words = btc.mnemonic.Mnemonic('english').generate(entsize)
	#print("Your Mnemonic is   %s" % words)
	if seed == None:
		seed = btc.mnemonic.Mnemonic().to_seed(words)
	hdk = btc.keys.HDKey.from_seed(seed, network=NETWORK)

	return {'seed':words, 'hdk':hdk}


def create_multisig_wallet(signers = 1, required=1, name = '', 
						   seeds = None, xpubs = None):	
	if seeds == None:  # it should create  random seeds
		seed_and_hdks = [create_seed_and_hdk() for i in range(signers)]
	else: # some seeds are available
		seed_and_hdks = []
		for i in range(signers):
			if seeds[i] == None: 
				seed_and_hdks.append(None)  
			else:
				seed_and_hdks.append(create_seed_and_hdk(seeds[i]))

	if xpubs == None:
		xpubs = [hdk['hdk'].public_master_multisig() for hdk in seed_and_hdks]
	

	for xpub, hdk in zip(xpubs, seed_and_hdks):
		if hdk != None:
			assert xpub == hdk['hdk'].public_master_multisig() 
		
		

	wallets = []
	for j in range(signers):
		if seed_and_hdks[j] == None:
			continue
		klist = [seed_and_hdks[j]['hdk'] if i == j else xpubs[i] for i in range(signers)]
		walletname = '_'.join([NETWORK, name, str(required), 'of', str(signers), 'cosigner', str(j)])
		
		btc.wallets.wallet_delete_if_exists(walletname, force = True)
		
		wallets.append(btc.wallets.HDWallet.create(
				  walletname, sigs_required=required, keys=klist,
	                      network=NETWORK))
		
		
	# Generate a new key in each wallet, all these keys should be the same
	keys = [wallet.new_key(cosigner_id=1) for wallet in wallets]
	for key in keys:
		assert keys[0].wif == key.wif
	#print("Created new multisig address: ", keys[0].wif)

	return {'seed_and_hdks':seed_and_hdks, 'wallets':wallets}
	

#%%



def setup_vault(seeds = None, xpubs = None):
	if seeds == None:
		seeds = {'vault' : None, 'release':None}
	if xpubs == None:
		xpubs = {'vault' : None, 'release':None}
	
	vault = create_multisig_wallet(signers=2, required=2, name='vault', 
								seeds = seeds['vault'], xpubs = xpubs['vault'])
	release = create_multisig_wallet(signers=3, required=2, name='release', 
								  seeds = seeds['release'], xpubs = xpubs['release'])
	return (vault, release)




def fund_vault(source_wallet, vault, amount = 10000, fee = 500):
	source_address = source_wallet.utxos()[0]['address']

	outputs = [(vault['wallets'][0].addresslist()[0], amount),
			(source_address, source_wallet.balance() - amount - fee)]
	input_arr = [btc.wallets.Input(
						utxo['tx_hash'], 
						utxo['output_n'],
#						script_type = utxo['script_type'], 
						value = utxo['value'],
						sequence= 2)
						for utxo in source_wallet.utxos()]
	tx = source_wallet.transaction_create( outputs, input_arr = input_arr , network=NETWORK)
	tx.sign()
#	tx.info()
	return tx



def ptx_vault2release(vault, release, funding_tx = None, lock_blocks = 0, fee = 800):
	V1 = vault['wallets'][0]
	
	if funding_tx == None:
		V1.utxos_update()
		input_utxos = V1.utxos()
	else:
		input_utxos = []
		for output in funding_tx.outputs:
#			print(V1.addresslist()[0])
			if output.address == V1.addresslist()[0]:
				utxo = {
						'value':output.value,
						'output_n':output.output_n,
						'spent':False,
						'address':output.address,
						'tx_hash':txid(funding_tx),
						'confirmations':0,
						'script':output.lock_script,
						'script_type':output.script_type,
						'network_name':NETWORK,
					}
				input_utxos.append( utxo)

#	print(input_utxos)
	outputs = [(release['wallets'][0].addresslist()[0], 
			 sum([inp['value'] for inp in input_utxos])-fee )]
#	print(outputs)
	
	V1.utxos_update(utxos = input_utxos)
	input_arr = [btc.wallets.Input(
						utxo['tx_hash'], 
						utxo['output_n'],
#						script_type = utxo['script_type'], 
						value = utxo['value'],
						sequence = lock_blocks)
						for utxo in input_utxos]
		
#	print(V1.utxos())
	tx = V1.transaction_create(outputs, input_arr=input_arr, network=NETWORK)
	tx.sign()
#	tx.info()
	return tx


def sign(wallet, tx):
	tx = wallet.transaction_import(tx)
	tx.sign()
	return tx





def ptx_release2final(release, receive_address, ptx_v2r = None, 
					  lock_blocks = 10, fee = 800):
	V2 = release['wallets'][0]
	if ptx_v2r == None:
		V2.utxos_update()
		input_utxos = V2.utxos()
	else:
		input_utxos = []
		for output in ptx_v2r.outputs:
			print(V2.addresslist()[0])
			if output.address == V2.addresslist()[0]:
				utxo = {
						'value':output.value,
						'output_n':output.output_n,
						'spent':False,
						'address':output.address,
						'tx_hash':txid(ptx_v2r),
						'confirmations':0,
						'script':output.lock_script,
						'script_type':output.script_type,
						'network_name':NETWORK,
					}
				input_utxos.append( utxo)

#	print(input_utxos)
	amount_total_input = sum([inp['value'] for inp in input_utxos])
	outputs = [(receive_address, amount_total_input - fee )]
#	print(outputs)
	
	V2.utxos_update(utxos = input_utxos)
	input_arr = [btc.wallets.Input(
						utxo['tx_hash'], 
						utxo['output_n'],
#						script_type = utxo['script_type'], 
						value = utxo['value'],
						sequence = lock_blocks)
						for utxo in input_utxos]

	tx = V2.transaction_create(outputs, input_arr = input_arr, network=NETWORK)
	tx.sign()
#	tx.info()
	return tx



#%%
	
def create_new_vault(seeds = None, xpubs = None, 
					 ptx_v2r = None, ptx_r2f = None, lock_blocks = 10,
					 fund_amount = 10000, source_private_key = None,
					 debug = True, verbose = False, final_address = None):
	
	if ptx_v2r != None and ptx_r2f != None:
		# If there are partial transactions you need the seeds to do anything
		assert seeds != None
		assert xpubs != None
	
	vault, release = setup_vault(seeds = seeds, xpubs = xpubs)
	
	if seeds == None:
		if verbose:
			print("\n=== Create the source wallet to fund the vault\n")
		btc.wallets.wallet_delete_if_exists('source wallet', force=True)
		source_wallet = btc.wallets.wallet_create_or_open(name='source wallet', network=NETWORK)
		#btc.wallets.wallet_empty(source_wallet)
		if source_private_key == None:
			source_private_key = '93Ko8tR86bDhx6SwhdZc1r7gV12xC3uMsVARn2uU5SpKpDG3PAj'
		source_wallet.import_key(source_private_key)
		source_wallet.utxos_update()
		if debug:
			source_wallet.utxos()
		
		#%%	
		
		if verbose:
			print("\n=== Source --> Vault \n")
		funding_tx = fund_vault(source_wallet, vault, amount = fund_amount)
		if verbose:
			pprint.pprint(funding_tx.as_dict())
#			funding_tx.send()
	
	if ptx_v2r == None:	
		if verbose:
			print("\n=== Vault --> Release (Partially signed) \n")	
		ptx_v2r = ptx_vault2release(vault, release, funding_tx=funding_tx)
		if verbose:
			pprint.pprint(ptx_v2r.as_dict())
	
	if debug:
		v2r_signed = sign(vault['wallets'][1], ptx_v2r)
		if verbose:
			print("\n=== Vault --> Release (signed) \n")
			pprint.pprint(v2r_signed.as_dict())
	else:
		v2r_signed = None

	
	if ptx_r2f == None:	
		if verbose:
			print("\n=== Release --> final (partiall signed, timelock) \n")
		if final_address == None:
			final_address = source_wallet.utxos()[0]['address']			
		ptx_r2f = ptx_release2final(release, final_address, 
										 ptx_v2r=ptx_v2r,
										 lock_blocks = lock_blocks )
		if verbose:
			pprint.pprint(ptx_r2f.as_dict())
	
	if debug:
		r2f_signed = sign(release['wallets'][1], ptx_r2f)
		if verbose:
			print("\n=== Release --> final (signed, timelock) \n")	
			pprint.pprint(r2f_signed.as_dict())
	else:
		r2f_signed = None
	
	
	
	if not debug:
		# delete unnecessary data
		
		# del V1
		vault['seed_and_hdks'][0]['seed'] = None
		#del V2
		release['seed_and_hdks'][0]['seed'] = None

	return_dict = {'seeds':{'vault': [hdk['seed'] for hdk in vault['seed_and_hdks'] if hdk['seed'] != None],
				  	'release':[hdk['seed'] for hdk in release['seed_and_hdks'] if hdk['seed'] != None]
							 }, 
			'xpubs':{'vault': [hdk['hdk'].public_master_multisig() for hdk in vault['seed_and_hdks']],
				 	'release':[hdk['hdk'].public_master_multisig() for hdk in release['seed_and_hdks']]
							 }, 
			'funding_tx':funding_tx.raw_hex(),
			'ptx_v2r': ptx_v2r.raw_hex(),
			'ptx_r2f': ptx_r2f.raw_hex(),
			}
	if v2r_signed != None:
		return_dict['v2r_signed'] = v2r_signed.raw_hex()
	if r2f_signed != None:
		return_dict['r2f_signed'] = r2f_signed.raw_hex()

	return return_dict

#%%





	
#%%
#print("\n=== The following seeds are necessary for you to store on paper: \n")
#print(vault['hdk'][1]['seed'])
	
	

#%%
print("""
===================================================
Welcome to the testnet bitcoin vault
===================================================
	  """)


debug_input = input("Run is debug mode (recommended) (Y/n): ")
debug = debug_input.lower() != "n"
print('Debug mode = '+str(debug))

lock_blocks_input = input("Number of blocks that the release is unspendable (default = 10): ")
if lock_blocks_input == "":
	lock_blocks = 10
else:
	lock_blocks = int(lock_blocks_input)

import_filename = input("""
To create a new wallet just press enter.
To load a data file, specify filename: 
						""")

	
	
if import_filename != "":
	if os.path.isfile(import_filename):
		with open(import_filename ,"rb") as file:
			data = pickle.load(file)
		
		print('.... please wait ...')		
		data = create_new_vault(seeds = data['seeds'], 
					  xpubs = data['xpubs'], 
					  ptx_v2r = data['ptx_v2r'], 
					  ptx_r2f = data['ptx_r2f'], 
					  lock_blocks = lock_blocks,
					  debug=debug)

		print(data)
	else:
		print(import_filename + " is not a valid filename.")

else:
	print('.... please wait ...')		
	data = create_new_vault( 
				  fund_amount = 10000,  # satoshis to redeem 
				  debug=debug,
				  verbose = True,
				  lock_blocks = lock_blocks,
				  )
	print("\n\n============================================================================")
	# save necessary data
	import_filename = str(datetime.datetime.now())+ ".pickle" 
	if not os.path.isfile(import_filename):
		with open(import_filename ,"wb") as file:
			pickle.dump(data, file)
			print('\nSaved data to ' + import_filename )
	
#	print(data)
	print("\n\n=== 1. ==========================")
	print("Funding transaction  (Source --> Vault = "+
							  btc.transactions.Transaction.import_raw(data['funding_tx']).outputs[0].address
							  +"): \n"+
	   "Boradcast here:  https://tbtc.bitaps.com/broadcast \n\n" 
	   + data['funding_tx'] + '\n')	
	
	print("\n\n=== 2. ==========================")
	print("Unlock vault transaction (partially signed)  (Vault --> Release = "+
							  btc.transactions.Transaction.import_raw(data['ptx_v2r']).outputs[0].address
							  +"): \n"+
	   " Boradcast here:  https://tbtc.bitaps.com/broadcast \n\n" 
	   + data['ptx_v2r'] + '\n')
	if 'v2r_signed' in data:
		print("Unlock transaction (signed)  (Vault --> Release): \n\n" 
		+ data['v2r_signed'] + '\n')		
	if len(data['seeds']['vault']) > 1:
		print("V1: " + data['seeds']['vault'][0] + '\n')
		print("R1: " + data['seeds']['vault'][1] + '\n')
	else:
		print("R1: " + data['seeds']['vault'][0] + '\n')
		
	
	
	print("\n\n=== 3. ==========================")
	print("Release transaction (partially signed)  (Release --> Final = "+
							  btc.transactions.Transaction.import_raw(data['ptx_r2f']).outputs[0].address
							  +"): \n"+
	   " Boradcast here:  https://tbtc.bitaps.com/broadcast AFTER "+
	   str(lock_blocks) +" Blocks\n\n" 
	   + data['ptx_r2f'] + '\n')
	if 'v2r_signed' in data:
		print("Release (signed)  (Release --> Final): \n\n" 
		+ data['r2f_signed'] + '\n')
	if len(data['seeds']['release']) > 2:
		print("V2: " + data['seeds']['release'][0] + '\n')
		print("R2: " + data['seeds']['release'][1] + '\n')
		print("E: " + data['seeds']['release'][2] + '\n')
	else:
		print("R2: " + data['seeds']['release'][0] + '\n')
		print("E (keep this in cold storage): " + data['seeds']['release'][1] + '\n')
	
	
	
	


		
	
		
	
	
	
#%%



