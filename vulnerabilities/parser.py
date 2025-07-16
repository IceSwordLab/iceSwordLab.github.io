#!python3
# -*- coding: utf-8 -*-

import os

import sys

import logging

import argparse

import time

import datetime

import configparser

import codecs

import functools


logger = logging.getLogger( "parser" )


def write_text_file( arg_filename , content ):

	filename =  arg_filename

	if not os.path.isabs(arg_filename):
		filename = os.path.abspath( arg_filename )

	dirname = os.path.dirname( filename )

	if not os.path.exists( dirname ):
		os.mkdir( dirname )
	
	fd = codecs.open( filename , mode='w' , encoding='utf-8' )

	fd.write( content )

	fd.close()

	return True

	
def read_text_file( arg_filename  ):
	
	filename =  arg_filename

	if not os.path.isabs(arg_filename):
		filename = os.path.abspath( arg_filename )

	fd = codecs.open( filename , mode='r' , encoding='utf-8' )

	content = fd.read()

	fd.close()

	return content


def parse_cve_text( cve_text ):

	items = cve_text.split('-' )

	return {

		"year" : items[1] ,

		"idx" : items[2]
	}

def cve_cmp_routine( cve1 , cve2):

	if ( cve1["year"] > cve2["year"] ):
		return 1
	elif ( cve1["year"] < cve2["year"] ):
		return -1

	return cve1["idx"] - cve2["idx"]

	

def load_source( src_filename  ):

	content = read_text_file( src_filename )

	old_lines = content.split('\n')


	cve_list = []


	for line_text in old_lines:
		line_text = line_text.strip()

		if 0 == len(line_text):
			continue
		else:
			pass

		raw_items = line_text.split('|' )

		fixed_items = []

		for item_text in raw_items:
			item_text = item_text.strip()

			if 0 == len(item_text):
				continue
			else:
				pass

			fixed_items.append( item_text )

		assert( 4 == len(fixed_items) )

		cve_text = fixed_items[0].lower()

		cve_key = parse_cve_text( cve_text )

		cve_info = {

			"cve"	: cve_text ,
			
			"year" 	: int(cve_key["year"]) ,

			"idx"	: int( cve_key["idx"]) ,

			"vendor" : fixed_items[1].lower() ,

			"type" : fixed_items[2] ,

			"credit" : fixed_items[3] 
		}

		cve_list.append( cve_info )
	

	cve_list =  sorted( cve_list , key=functools.cmp_to_key( cve_cmp_routine ) )

	cve_table = {}

	for item in cve_list:

		key ='{0}_{1}'.format(  item["cve"] , item['vendor'] )

		if key in cve_table:
			
			print('[!] find duplicate cve {0} with vendor "{1}"'.format( item["cve"] , item["vendor"] ) )
		
		else:
			cve_table[ key ] = item


	cve_list = cve_table.values()

	cve_list =  sorted( cve_list , key=functools.cmp_to_key( cve_cmp_routine ) )

	return cve_list



def build_source_file( cve_list  ):

	cve_index = 0

	cve_count = len(cve_list)

	index_format = "%d"

	if cve_count >= 100000:
		index_format = "%06d"
	elif cve_count >= 10000:
		index_format = "%05d"
	elif cve_count >= 1000:
		index_format = "%04d"
	elif cve_count >= 100:
		index_format = "%03d"
	elif cve_count >= 10:
		index_format = "%02d"
	else:
		index_format = "%d"


	table_body = ''

	for cve_item in cve_list:

		fix_vendor_name = cve_item["vendor"][0].upper() + cve_item["vendor"][1:]


		table_body += '{0}\t|{1}\t|{2}\t|{3}\r\n'.format(
			
			cve_item["cve"] ,

			fix_vendor_name ,

			cve_item["type"],

			cve_item["credit"] 
		)

		cve_index += 1

	return  table_body


def build_all_in_one_md_table( cve_list  ):


	cve_index = 0

	cve_count = len(cve_list)

	index_format = "%d"

	if cve_count >= 100000:
		index_format = "%06d"
	elif cve_count >= 10000:
		index_format = "%05d"
	elif cve_count >= 1000:
		index_format = "%04d"
	elif cve_count >= 100:
		index_format = "%03d"
	elif cve_count >= 10:
		index_format = "%02d"
	else:
		index_format = "%d"

	table_head = '# All Acknowlegements {0}\r\n'.format( cve_count )

	table_head += '|#|CVE|Vendor|Type|Credit\r\n'

	table_head += '|------|------|------|------|------\r\n'

	table_body = ''

	for cve_item in cve_list:

		fix_vendor_name = cve_item["vendor"][0].upper() + cve_item["vendor"][1:]

		table_body += '|{0}\t|{1}\t|{2}\t|{3}\t|{4}\r\n'.format(
			
			index_format % ( cve_index + 1 ) ,

			cve_item["cve"] ,

			fix_vendor_name ,

			cve_item["type"],

			cve_item["credit"] 
		)

		cve_index += 1

	return table_head + table_body




def build_sub_md_table( vendor_name , cve_list ):

	cve_index = 0

	cve_count = len(cve_list)

	index_format = "%d"

	if cve_count >= 100000:
		index_format = "%06d"
	elif cve_count >= 10000:
		index_format = "%05d"
	elif cve_count >= 1000:
		index_format = "%04d"
	elif cve_count >= 100:
		index_format = "%03d"
	elif cve_count >= 10:
		index_format = "%02d"
	else:
		index_format = "%d"

	fix_vendor_name = vendor_name[0].upper() + vendor_name[1:]

	table_head = '## {0} ({1})\r\n'.format( fix_vendor_name , cve_count )

	table_head += '------\r\n'

	table_head += '|CVE|Type|Credit\r\n'

	table_head += '|------|------|------\r\n'

	table_body = ''

	for cve_item in cve_list:

		table_body += '|{0}\t|{1}\t|{2}\r\n'.format(
			
			#index_format % ( cve_index + 1 ) ,

			cve_item["cve"].upper() ,

			cve_item["type"],

			cve_item["credit"] 
		)

		cve_index += 1


	return table_head + table_body



def vendor_cmp_routine( vendor1 , vendor2 ):

	return len(vendor2[1]) - len(vendor1[1])

	

def batch_build_sub_md_table( cve_list ):

	vendor_name_table = {}

	vendor_name = ''

	for cve_item in cve_list:
		vendor_name = cve_item["vendor"]

		if vendor_name in vendor_name_table:
			vendor_name_table[ vendor_name ].append( cve_item )
		else:
			vendor_name_table[ vendor_name ] = [ cve_item]
	
	
	vendor_list = []

	for vendor_name in vendor_name_table:
		vendor_list.append( ( vendor_name , vendor_name_table[vendor_name] ) )


	vendor_list = sorted( vendor_list , key=functools.cmp_to_key( vendor_cmp_routine ) )
		
	content = ''

	for item in vendor_list:
		content += build_sub_md_table( item[0] , item[1] ) + '\r\n\r\n\r\n\r\n'

	return content


def write_source_file( cve_list , ):


	content = build_source_file( cve_list )

	write_text_file( "source.txt" , content )

	
def write_all_in_one_md_file( cve_list ):

	content = ''

	content += "---\r\n"
	content += "title: Acknowlegement we received\r\n"
	content += "date: 2017-06-01 17:01:34\r\n"
	content += "---\r\n"

	content += "\r\n"

	content += build_all_in_one_md_table( cve_list )

	write_text_file( "output/all.md" , content )


def write_index_md_file( cve_list ):

	content = ''

	content += "---\r\n"
	content += "title: Acknowlegement we received\r\n"
	content += "date: 2017-06-01 17:01:34\r\n"
	content += "---\r\n"

	content += "\r\n"

	content += batch_build_sub_md_table( cve_list )

	write_text_file( "index.md" , content )


def main():
	parser = argparse.ArgumentParser( description="parser" , )

	logger.setLevel( logging.INFO )

	console_logger = logging.StreamHandler()
	console_logger.setLevel(logging.INFO )
	logger.addHandler(console_logger)

	#
	logger.info("[+] start" )

	work_dir = os.path.split(os.path.realpath(__file__))[0]
	os.chdir(work_dir)
	
	cve_list = []

	cve_list = load_source( "source.txt")

	# final

	write_source_file( cve_list )

	write_index_md_file( cve_list )

	logger.info("[+] done" )

	return

if __name__ == "__main__":
	main()
  









