# coding=utf-8
from __future__ import absolute_import
from __future__ import unicode_literals

import flask
import octoprint.plugin
import octoprint.filemanager
import octoprint.filemanager.util
import octoprint.util
import os
import datetime
import io
from PIL import Image
import re
import base64
import imghdr
import requests
import sys
import socket
import octoprint.events
import octoprint.printer
import urllib.request
import email
import random
import string
import json
import time

from octoprint.server import printer, fileManager, slicingManager, eventManager, NO_CONTENT
from octoprint.events import Events, eventManager
from octoprint.plugin import OctoPrintPlugin
from flask_babel import gettext
from octoprint.access import ADMIN_GROUP
from octoprint.access.permissions import Permissions
from octoprint.filemanager.destinations import FileDestinations

from octoprint.settings import settings

try:
	from urllib import quote, unquote
except ImportError:
	from urllib.parse import quote, unquote

timeout = 15
socket.setdefaulttimeout(timeout)

class E3S1PROFORKBYTTThumbnailsPlugin(octoprint.plugin.SettingsPlugin,
								octoprint.plugin.AssetPlugin,
								octoprint.plugin.TemplatePlugin,
								octoprint.plugin.EventHandlerPlugin,
								octoprint.plugin.StartupPlugin,
								octoprint.printer.PrinterCallback,
								octoprint.plugin.SimpleApiPlugin):

	def __init__(self):
		self.file_scanner = None
		self.syncing = False
		self._fileRemovalTimer = None
		self._fileRemovalLastDeleted = None
		self._fileRemovalLastAdded = None
		self._folderRemovalTimer = None
		self._folderRemovalLastDeleted = {}
		self._folderRemovalLastAdded = {}
		self._waitForAnalysis = False
		self._analysis_active = False
		self._plugin_version = "2.1.0"
		self.regex_extension = re.compile("\.(?:gco(?:de)?|tft)$")
		self.use_e3s1proforkbytt = False  # Initialize it as False here
		self.gcodeExt = "gcode"
		self.api_key = None
		self.hostIP = "127.0.0.1"
		self.octoPort = "5000"
		self.sslBool = "no"  # Set your default SSL option
		self.sendLoc = "sdcard"  # Set your default send location
		self.printBool = "false"  # Set your default print option
		self.selectBool = "false"  # Set your default select option
		self.selectedPrintFilename = "None"
		self.selectedPrintFileFoldername = "None"		
		self.octodgusFilename = "None"

	# ~~ SettingsPlugin mixin


	def get_settings_defaults(self):
		return {'installed': True, 'inline_thumbnail': False, 'scale_inline_thumbnail': False,
				'inline_thumbnail_scale_value': "50", 'inline_thumbnail_position_left': False,
				'align_inline_thumbnail': False, 'inline_thumbnail_align_value': "left", 'state_panel_thumbnail': True,
				'state_panel_thumbnail_scale_value': "100", 'resize_filelist': False, 'filelist_height': "306",
				'scale_inline_thumbnail_position': False, 'sync_on_refresh': False, 'use_uploads_folder': True,
				'relocate_progress': False, 'api_key': "NOAPIKEY"}

	# ~~ AssetPlugin mixin

	def get_assets(self):
		return {'js': ["js/e3s1proforkbyttthumbnails.js"], 'css': ["css/e3s1proforkbyttthumbnails.css"]}

	# ~~ TemplatePlugin mixin

	def get_template_configs(self):
		return [
			{'type': "settings", 'custom_bindings': False, 'template': "e3s1proforkbyttthumbnails_settings.jinja2"},
		]

	def delete_existing_file(self, filename, file_location):
		self._logger.debug("E3S1PROFORKBYTT delete_existing_file is %s.", filename)	
		if file_location == "sdcard":
			url = f"http://{self.hostIP}:{self.octoPort}/api/files/sdcard/{filename}"
		else:
			url = f"http://{self.hostIP}:{self.octoPort}/api/files/local/{filename}"
		headers = {
			'User-agent': 'Cura AutoUploader Plugin',
			'X-Api-Key': self.api_key,
		}
		try:
			response = requests.delete(url, headers=headers)
			if response.status_code == 204:
				self._logger.debug("E3S1PROFORKBYTT delete_existing_file is %s.", filename)
			elif response.status_code == 404:
				self._logger.debug("E3S1PROFORKBYTT delete_existing_file not found %s.", filename)
			else:
				self._logger.debug("E3S1PROFORKBYTT delete_existing_file failed for %s.", filename)
		except requests.exceptions.RequestException as e:
			self._logger.debug("E3S1PROFORKBYTT request response error for: ", e)

	def generate_boundary(self):
		return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(30))

	def send_file(self, filename, gcode_filename):
		outputName = os.path.split(filename)[1]
		if self.sslBool == "yes":
			protocol = "https://"
		else:
			protocol = "http://"
		if self.sendLoc == "sdcard":
			url = protocol + self.hostIP + ":" + self.octoPort + "/api/files/sdcard"
		else:
			url = protocol + self.hostIP + ":" + self.octoPort + "/api/files/local"
		if self.selectBool not in ('yes', 'no'):
			self.selectBool = 'no'
		self._logger.debug("Select: ", self.selectBool)
		if self.printBool not in ('yes', 'no'):
			self.printBool = 'no'
		self._logger.debug("Print: ", self.printBool)
		self._logger.debug("filename before: ", filename)
		filename = self._file_manager.path_on_disk("local", filename)
		self._logger.debug("filename openafter: ", filename)
		filebody = open(filename, 'rb').read()
		mimetype = 'application/octet-stream'
		boundary = self.generate_boundary()
		content_type = 'multipart/form-data; boundary=%s' % boundary
		body = []
		body_boundary = '--' + boundary
		body = [body_boundary,
			'Content-Disposition: form-data; name="file"; filename="%s"' % outputName,
			'Content-Type: %s' % mimetype,
			'',
			]
		body.append(filebody.decode('utf-8'))
		body += [
			body_boundary,
			'Content-Disposition: form-data; name="select"',
			'',
			self.selectBool,
			body_boundary,
			'Content-Disposition: form-data; name="print"',
			'',
			self.printBool,
			body_boundary + '--',
		]
		body.append('')
		body = '\r\n'.join(body)
		self._logger.debug("E3S1PROFORKBYTT send_file body  is %s.", str(body))		
		req = urllib.request.Request(url)
		req.add_header('User-agent', 'Cura AutoUploader Plugin')
		req.add_header('Content-type', content_type)
		req.add_header('Content-length', len(body))
		req.add_header('X-Api-Key', self.api_key)
		req.data = body.encode('utf-8')
		self._logger.debug("Uploading...")
		self._logger.debug("url send_file is %s", str(url))
		with urllib.request.urlopen(req) as response:
			print(response.read().decode('utf-8'))
		self._logger.debug("E3S1PROFORKBYTT send_file gcode_filename  is %s.", gcode_filename)
		self._logger.debug("Done...")

	def prepare_file(self, infile, gcode_filename):
		if not os.path.isabs(infile):
			infile = os.path.abspath(infile)
		outputName = os.path.splitext(os.path.basename(infile))[0]
		self._logger.debug("E3S1PROFORKBYTT prepare_file1 is: %s", outputName)
		outputName = outputName + "." + self.gcodeExt
		outputName2 = "OCTODGUS.GCO"
		self._logger.debug("E3S1PROFORKBYTT prepare_file2 is: %s", outputName)
		self._logger.debug("E3S1PROFORKBYTT prepare_file gcode_filename  is %s.", gcode_filename)
		self.send_file(outputName, gcode_filename)

	def _extract_thumbnail(self, gcode_filename, thumbnail_filename):
		regex = r"(?:^; thumbnail(?:_JPG)* begin \d+[x ]\d+ \d+$)(?:\n|\r\n?)((?:.+(?:\n|\r\n?))+?)(?:^; thumbnail(?:_JPG)* end)"
		regex_e3s1proforkbytt_content = r"(?:^; (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(?:^; (?:thumbnail(?:_JPG)*|jpg) end|\Z)"
		regex_e3s1proforkbytt_full = r"(^; (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(^; (?:thumbnail(?:_JPG)*|jpg) end|\Z)"
		lineNum = 0
		collectedString = ""
		use_e3s1proforkbytt = False
		with open(gcode_filename, "r", encoding="utf8", errors="ignore") as gcode_file:
			for line in gcode_file:
				lineNum += 1
				gcode = octoprint.util.comm.gcode_command_for_cmd(line)
				extrusion_match = octoprint.util.comm.regexes_parameters["floatE"].search(line)
				if gcode == "G1" and extrusion_match:
					self._logger.debug("Line %d: Detected first extrusion. Read complete.", lineNum)
					break
				if line.startswith(";") or line.startswith("\n") or line.startswith("M10086 ;") or line[0:4] in ["W220", "W221", "W222"]:
					collectedString += line
			self._logger.debug(collectedString)
			test_str = collectedString.replace(octoprint.util.to_unicode('\r\n'), octoprint.util.to_unicode('\n'))
		test_str = test_str.replace(octoprint.util.to_unicode(';\n;\n'), octoprint.util.to_unicode(';\n\n;\n'))
		matches_e3s1proforkbytt_content = re.findall(regex_e3s1proforkbytt_content, test_str, re.MULTILINE)
		matches_e3s1proforkbytt_full = re.findall(regex_e3s1proforkbytt_full, test_str, re.MULTILINE)
		if len(matches_e3s1proforkbytt_content) > 0:
			use_e3s1proforkbytt = True
			self.use_e3s1proforkbytt = use_e3s1proforkbytt  # Update the instance variable
			matches_e3s1proforkbytt_content = re.findall(regex_e3s1proforkbytt_content, test_str, re.MULTILINE)
			if len(matches_e3s1proforkbytt_content) > 0:
				self._logger.debug("E3S1PROFORKBYTT thumbnail jpg written to %s.", thumbnail_filename)
				maxlen_e3s1proforkbytt=0
				choosen_e3s1proforkbytt=-1
				for i in range(len(matches_e3s1proforkbytt_content)):
					curlen_e3s1proforkbytt=len(matches_e3s1proforkbytt_content[i])
					if maxlen_e3s1proforkbytt<curlen_e3s1proforkbytt:
						maxlen_e3s1proforkbytt=curlen_e3s1proforkbytt
						choosen_e3s1proforkbytt=i
				path = os.path.dirname(thumbnail_filename)
				if not os.path.exists(path):
					os.makedirs(path)
				with open(thumbnail_filename, "wb") as jpg_file:
					jpg_file.write(self._extract_e3s1proforkbytt_thumbnail(matches_e3s1proforkbytt_content[choosen_e3s1proforkbytt]))

	def _extract_transferfile(self, gcode_filename, printer_thumbnail_filename):
		collectedString = ""
		lineNum = 0
		regex_e3s1proforkbytt_full = r"(^; (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(^; (?:thumbnail(?:_JPG)*|jpg) end|\Z)"
		regex_e3s1proforkbytt_final = r"(^M4010 (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(^M4010 (?:thumbnail(?:_JPG)*|jpg) end|\Z)"		
		with open(gcode_filename, "r", encoding="utf8", errors="ignore") as gcode_file:
			replace_next_line = False
			for line in gcode_file:
				lineNum += 1
				gcode = octoprint.util.comm.gcode_command_for_cmd(line)
				extrusion_match = octoprint.util.comm.regexes_parameters["floatE"].search(line)
				if line.startswith(";"):
					replace_next_line = True
				if replace_next_line:
					line = "M4010" + line[1:]
					replace_next_line = False
				collectedString += line
				if gcode == "G1" and extrusion_match:
					self._logger.debug("Line %d: Detected first extrusion. Read complete.", lineNum)
					break
			self._logger.debug(collectedString)
			test_str = collectedString.replace(octoprint.util.to_unicode('\r\n'), octoprint.util.to_unicode('\n'))
		test_str = test_str.replace(octoprint.util.to_unicode(';\n;\n'), octoprint.util.to_unicode(';\n\n;\n'))
		matches_e3s1proforkbytt_final = re.findall(regex_e3s1proforkbytt_final, test_str, re.MULTILINE)
		if len(matches_e3s1proforkbytt_final) > 0:
			path = os.path.dirname(printer_thumbnail_filename)
			if not os.path.exists(path):
				os.makedirs(path)
			self._logger.debug("E3S1PROFORKBYTT _extract_transferfile gcode_filename  is %s.", gcode_filename)
			self._logger.debug("E3S1PROFORKBYTT _extract_transferfile printer_thumbnail_filename is %s.", printer_thumbnail_filename)
			self._write_lines_to_text_file(printer_thumbnail_filename, matches_e3s1proforkbytt_final, gcode_filename)

	def _write_lines_to_text_file(self, printer_thumbnail_filename, lines, gcode_filename):
		with open(printer_thumbnail_filename, 'w', encoding='utf-8') as f:
			for line_tuple in lines:
				line_str = ''.join(line_tuple)
				f.write(line_str + '\n')
		self._logger.debug("E3S1PROFORKBYTT _write_lines_to_text_filel written to %s.", printer_thumbnail_filename)
		self._logger.debug("E3S1PROFORKBYTT _write_lines_to_text_file gcode_filename  is %s.", gcode_filename)
		self.prepare_file(printer_thumbnail_filename, gcode_filename)

	# Extracts a thumbnail from hex binary data usd by Qidi slicer
	def _extract_e3s1proforkbytt_thumbnail(self, match):
		encoded_jpg = base64.b64decode(match.replace("; ", "").encode())
		with io.BytesIO(encoded_jpg) as jpg_bytes:
			image = Image.open(jpg_bytes)
			return self._imageToJpg(image)

	def _imageToJpg(self, image):
		# Save image as jpeg (jpg)
		with io.BytesIO() as jpg_bytes:
			image.save(jpg_bytes, "JPEG")
			jpg_bytes_string = jpg_bytes.getvalue()

		return jpg_bytes_string

	# ~~ EventHandlerPlugin mixin

	def on_event(self, event, payload):
		self._logger.debug("event all is %s", str(event))
		self._logger.debug("API Key 'E3S1PROFORKBYTT_Thumbnails': %s" % self.api_key)
		self._logger.debug("self.selectedPrintFilename on event is %s", str(self.selectedPrintFilename))
		self._logger.debug("self.octodgusFilename on event is %s", str(self.octodgusFilename))
		if event == "FileSelected":
			self._logger.debug("payload[name] on event is %s", str(payload["name"]))		
		if event == "PrintStarted" and self.octodgusFilename != "octodgus.gcode" and self.octodgusFilename == "None" and payload["name"] != "octodgus.gcode" and self.selectedPrintFilename != "None":
			self._logger.debug("event PrintStarted")
			octodgusStarted = f"M19 S3 ; Update LCD"
			self._printer.commands(octodgusStarted)
			self._logger.debug("M19 S3 sent to LCD Display: %s", str(octodgusStarted))
			display_name = os.path.splitext(os.path.basename(self.selectedPrintFilename))[0]
			display_name = str(display_name)
			fileStartedM117 = f"M117 {display_name} ; Update LCD"
			self._printer.commands(fileStartedM117)
			self._logger.debug("Sending M117 display_name on Printstart to LCD display: %s", str(fileStartedM117))				
			self._logger.debug("self.selectedPrintFilename set to: %s", str(self.selectedPrintFilename))
		if event == "PrintResumed" and self.selectedPrintFilename != "None":
			self._logger.debug("event PrintResumed")
			octodgusResumed = f"M19 S5 ; Update LCD"
			self._printer.commands(octodgusResumed)
			self._logger.debug("M19 S5 sent to LCD Display: %s", str(octodgusResumed))
			self._logger.debug("self.selectedPrintFilename set to: %s", str(self.selectedPrintFilename))
		if event == "PrintCancelled" and self.selectedPrintFilename != "None":
			self._logger.debug("event PrintCancelled")
			octodgusCancelled = f"M19 S2 ; Update LCD"
			self._printer.commands(octodgusCancelled)
			self._logger.debug("M19 S2 sent to LCD Display: %s", str(octodgusCancelled))
			self.selectedPrintFilename = "None"
			self._logger.debug("self.selectedPrintFilename set to: %s", str(self.selectedPrintFilename))
		if event == "PrintPaused" and self.selectedPrintFilename != "None":
			self._logger.debug("event PrintPaused")
			octodgusPaused = f"M19 S4 ; Update LCD"
			self._printer.commands(octodgusPaused)
			self._logger.debug("M19 S4 sent to LCD Display: %s", str(octodgusPaused))
			self._logger.debug("self.selectedPrintFilename set to: %s", str(self.selectedPrintFilename))
		if event == "PrintDone" and self.selectedPrintFilename != "None":
			self._logger.debug("event PrintDone")
			octodgusPrintdone = f"M19 S6 ; Update LCD"
			self._printer.commands(octodgusPrintdone)
			self._logger.debug("M19 S6 sent to LCD Display: %s", str(octodgusPrintdone))
			self.selectedPrintFilename = "None"
			self._logger.debug("self.selectedPrintFilename set to: %s", str(self.selectedPrintFilename))
		if event == "TransferDone" and self.octodgusFilename == 'octodgus.gcode':
			self._logger.debug("self.selectedPrintFilename on TransferDone is %s", str(self.selectedPrintFilename))
			self._logger.debug("self.selectedPrintFileFoldername on TransferDone is %s", str(self.selectedPrintFileFoldername))			
			self._logger.debug("self.octodgusFilename on event is %s", str(self.octodgusFilename))
			file_location = "local"
			delete_file_local = "octodgus.gcode"
			self._file_manager.remove_file(file_location, delete_file_local)
			self._logger.debug("event TransferDone octodgus.gcode deleted local file %s.", str(delete_file_local))
			path_select_absolute = os.path.join(self.selectedPrintFileFoldername, self.selectedPrintFilename)
			self._logger.debug("path_select_absolute on TransferDone is %s", str(path_select_absolute))				
			path_select_file = self._file_manager.path_on_disk(file_location, path_select_absolute)
			self._logger.debug("path_select_file on TransferDone is %s", str(path_select_file))				
			self._printer.select_file(path_select_file, False, False)
			loadOCTODGUS = f"M19 S1 ; Update LCD"
			self._printer.commands(loadOCTODGUS)
			self._logger.debug("loadOCTODGUS file loaded: %s", str(loadOCTODGUS))
			display_name = os.path.splitext(os.path.basename(self.selectedPrintFilename))[0]
			display_name = str(display_name)
			fileLoadedM117 = f"M117 {display_name} ; Update LCD"
			self._printer.commands(fileLoadedM117)
			self._logger.debug("Sending M117 display_name to LCD display: %s", str(fileLoadedM117))	
			self.octodgusFilename = "None"
			self._logger.debug("self.octodgusFilename set to: %s", str(self.octodgusFilename))
		if event not in ["FileAdded", "FileRemoved", "FolderRemoved", "FolderAdded", "FileSelected", "PrintStarted"]:
			return
		if event == "FolderRemoved" and payload["storage"] == "local":
			import shutil
			shutil.rmtree(self.get_plugin_data_folder() + "/" + payload["path"], ignore_errors=True)
		if event == "FolderAdded" and self.octodgusFilename != "octodgus.gcode" and payload["storage"] == "local":
			file_list = self._file_manager.list_files(path=payload["path"], recursive=True)
			local_files = file_list["local"]
			results = dict(no_thumbnail=[], no_thumbnail_src=[])
			for file_key, file in local_files.items():
				results = self._process_gcode(local_files[file_key], results)
			self._logger.debug("Scan results: {}".format(results))
		if event in ["FileAdded", "FileRemoved"] and payload["storage"] == "local" and payload["name"] == "octodgus.gcode":
			self._logger.debug("event FileAdded/FileRemoved octodgus.gcode found. Abborting!!!")
			return
		if event in ["FileAdded", "FileRemoved"] and payload["name"] != "octodgus.gcode" and payload["storage"] == "local" and payload.get("name", False):
			file_extension = os.path.splitext(payload["name"])[1].lower()
			self._logger.debug("event FileAdded first")
			if file_extension != ".gcode":
				return  # Skip non-gcode files
			thumbnail_name_jpg = self.regex_extension.sub(".jpg", payload["name"])			
			thumbnail_path_jpg = self.regex_extension.sub(".jpg", payload["path"])
			regex_e3s1proforkbytt_content = r"(?:^; (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(?:^; (?:thumbnail(?:_JPG)*|jpg) end|\Z)"
			gcode_filename = self._file_manager.path_on_disk("local", payload["path"])
			with open(gcode_filename, "rb") as gcode_file:
				gcode_content = gcode_file.read().decode("utf-8", "ignore")
				if re.search(regex_e3s1proforkbytt_content, gcode_content, re.MULTILINE):
					self.use_e3s1proforkbytt = True
					use_e3s1proforkbytt = True
				else:
					self.use_e3s1proforkbytt = False
					use_e3s1proforkbytt = False
			if not self._settings.get_boolean(["use_uploads_folder"]):
				thumbnail_filename = "{}/{}".format(self.get_plugin_data_folder(), thumbnail_path_jpg)
			else:
				thumbnail_filename = self._file_manager.path_on_disk("local", thumbnail_path_jpg)
			if os.path.exists(thumbnail_filename):
				os.remove(thumbnail_filename)
			if event == "FileAdded" and self.octodgusFilename != "octodgus.gcode":
				self._logger.debug("event FileAdded inside")
				gcode_filename = self._file_manager.path_on_disk("local", payload["path"])
				self._extract_thumbnail(gcode_filename, thumbnail_filename)
				if os.path.exists(thumbnail_filename):
					thumbnail_url = "plugin/e3s1proforkbyttthumbnails/thumbnail/{}?{:%Y%m%d%H%M%S}".format(thumbnail_path_jpg.replace(thumbnail_name_jpg, quote(thumbnail_name_jpg)), datetime.datetime.now())
					self._file_manager.set_additional_metadata("local", payload["path"], "thumbnail", thumbnail_url.replace("//", "/"), overwrite=True)
					self._file_manager.set_additional_metadata("local", payload["path"], "thumbnail_src", self._identifier, overwrite=True)
		if event == "FileSelected" and self.octodgusFilename == "octodgus.gcode" and payload["name"] == "octodgus.gcode":
			self._logger.debug("event FileSelected 1")
			self._logger.debug("self.octodgusFilename is %s", self.octodgusFilename )
			self.octodgusFilename = "None"
			self._logger.debug("self.octodgusFilename is %s", self.octodgusFilename )
		if event == "FileSelected" and (self.selectedPrintFilename == "None" or self.selectedPrintFilename != payload["name"]):
			self._logger.debug("event FileSelected 2")
			file_extension = os.path.splitext(payload["name"])[1].lower()
			if file_extension != ".gcode":
				return  # Skip non-gcode files
			thumbnail_name_jpg = self.regex_extension.sub(".jpg", payload["name"])			
			thumbnail_path_jpg = self.regex_extension.sub(".jpg", payload["path"])			
			regex_e3s1proforkbytt_content = r"(?:^; (?:thumbnail(?:_JPG)*|jpg) begin 250x250 \d+ 1 \d+(?:\s+\d+)*.*?$)([\s\S]*?)(?:^; (?:thumbnail(?:_JPG)*|jpg) end|\Z)"
			gcode_filename = self._file_manager.path_on_disk("local", payload["path"])
			with open(gcode_filename, "rb") as gcode_file:
				gcode_content = gcode_file.read().decode("utf-8", "ignore")
				if re.search(regex_e3s1proforkbytt_content, gcode_content, re.MULTILINE):
					self.use_e3s1proforkbytt = True
					use_e3s1proforkbytt = True
				else:
					self.use_e3s1proforkbytt = False
					use_e3s1proforkbytt = False			
			if not self._settings.get_boolean(["use_uploads_folder"]):
				thumbnail_filename = "{}/{}".format(self.get_plugin_data_folder(), thumbnail_path_jpg)
			else:
				thumbnail_filename = self._file_manager.path_on_disk("local", thumbnail_path_jpg)
			if os.path.exists(thumbnail_filename):
				os.remove(thumbnail_filename)
			self._extract_thumbnail(gcode_filename, thumbnail_filename)
			if os.path.exists(thumbnail_filename):
				thumbnail_url = "plugin/e3s1proforkbyttthumbnails/thumbnail/{}?{:%Y%m%d%H%M%S}".format(thumbnail_path_jpg.replace(thumbnail_name_jpg, quote(thumbnail_name_jpg)), datetime.datetime.now())
				self._file_manager.set_additional_metadata("local", payload["path"], "thumbnail", thumbnail_url.replace("//", "/"), overwrite=True)
				self._file_manager.set_additional_metadata("local", payload["path"], "thumbnail_src", self._identifier, overwrite=True)
			self._logger.debug("payload name: ", payload["name"])
			printer_thumbnail_filename = "octodgus.gcode"
			self.selectedPrintFilename = os.path.split(gcode_filename)[1]
			self.selectedPrintFileFoldername = os.path.split(gcode_filename)[0]			
			self.octodgusFilename = printer_thumbnail_filename
			if not self._settings.get_boolean(["use_uploads_folder"]):
				printer_thumbnail_filename = "{}/{}".format(self.get_plugin_data_folder(), thumbnail_path_jpg)
			else:
				printer_thumbnail_filename = self._file_manager.path_on_disk("local", printer_thumbnail_filename)
			self._logger.debug("self.octodgusFilename on event FileSelected is %s", str(self.octodgusFilename))
			self._logger.debug("self.selectedPrintFilename on event FileSelected is %s", str(self.selectedPrintFilename))
			self._logger.debug("self.selectedPrintFileFoldername on event FileSelected is %s", str(self.selectedPrintFileFoldername))			
			self._logger.debug("printer_thumbnail_filename is %s", printer_thumbnail_filename)
			self._logger.debug("gcode_filename is %s", str(gcode_filename))
			self._extract_transferfile(gcode_filename, printer_thumbnail_filename)

	# ~~ SimpleApiPlugin mixin

	def _process_gcode(self, gcode_file, results=None):
		if results is None:
			results = []
		self._logger.debug(gcode_file["path"])
		if gcode_file.get("type") == "machinecode":
			self._logger.debug(gcode_file.get("thumbnail"))
			if gcode_file.get("thumbnail") is None or not os.path.exists("{}/{}".format(self.get_plugin_data_folder(), self.regex_extension.sub(".png", gcode_file["path"]))):
				self._logger.debug("No Thumbnail for %s, attempting extraction" % gcode_file["path"])
				results["no_thumbnail"].append(gcode_file["path"])
				self.on_event("FileAdded", {'path': gcode_file["path"], 'storage': "local", 'type': ["gcode"],
											'name': gcode_file["name"]})
			elif "e3s1proforkbyttthumbnails" in gcode_file.get("thumbnail") and not gcode_file.get("thumbnail_src"):
				self._logger.debug("No Thumbnail source for %s, adding" % gcode_file["path"])
				results["no_thumbnail_src"].append(gcode_file["path"])
				self._file_manager.set_additional_metadata("local", gcode_file["path"], "thumbnail_src",
														   self._identifier, overwrite=True)
		elif gcode_file.get("type") == "folder" and not gcode_file.get("children") == None:
			children = gcode_file["children"]
			for key, file in children.items():
				self._process_gcode(children[key], results)
		return results

	def on_after_startup(self):
		# Access the API key from the settings
		self.api_key = self._settings.get(["api_key"])

	def get_api_commands(self):
		return dict(crawl_files=[])

	def on_api_command(self, command, data):
		import flask
		if not Permissions.PLUGIN_E3S1PROFORKBYTTTHUMBNAILS_SCAN.can():
			return flask.make_response("Insufficient rights", 403)

		if command == "crawl_files":
			return flask.jsonify(self.scan_files())

	def scan_files(self):
		self._logger.debug("Crawling Files")
		file_list = self._file_manager.list_files(recursive=True)
		self._logger.debug(file_list)
		local_files = file_list["local"]
		results = dict(no_thumbnail=[], no_thumbnail_src=[])
		for key, file in local_files.items():
			if local_files[key] != "OCTODGUS.GCO" and local_files[key] != "octodgus.gcode":
				results = self._process_gcode(local_files[key], results)
		self.file_scanner = None
		return results

	# ~~ extension_tree hook
	def get_extension_tree(self, *args, **kwargs):
		return dict(
			machinecode=dict(
				gcode=["txt"]
			)
		)

	# ~~ Routes hook
	def route_hook(self, server_routes, *args, **kwargs):
		from octoprint.server.util.tornado import LargeResponseHandler, path_validation_factory
		from octoprint.util import is_hidden_path
		thumbnail_root_path = self._file_manager.path_on_disk("local", "") if self._settings.get_boolean(["use_uploads_folder"]) else self.get_plugin_data_folder()
		return [
			(r"thumbnail/(.*)", LargeResponseHandler,
			 {'path': thumbnail_root_path, 'as_attachment': False, 'path_validation': path_validation_factory(
				 lambda path: not is_hidden_path(path), status_code=404)})
		]

	# ~~ Server API Before Request Hook

	def hook_octoprint_server_api_before_request(self, *args, **kwargs):
		return [self.update_file_list]

	def update_file_list(self):
		if self._settings.get_boolean(["sync_on_refresh"]) and flask.request.path.startswith(
				'/api/files') and flask.request.method == 'GET' and not self.file_scanner:
			from threading import Thread
			self.file_scanner = Thread(target=self.scan_files, daemon=True)
			self.file_scanner.start()

	# ~~ Access Permissions Hook

	def get_additional_permissions(self, *args, **kwargs):
		return [
			{'key': "SCAN", 'name': "Scan Files", 'description': gettext("Allows access to scan files."),
			 'roles': ["admin"], 'dangerous': True, 'default_groups': [ADMIN_GROUP]}
		]

	# ~~ Softwareupdate hook

	def get_update_information(self):
		return {'e3s1proforkbyttthumbnails': {'displayName': "E3S1PROFORKBYTT Thumbnails", 'displayVersion': self._plugin_version,
										  'type': "github_release", 'user': "jneilliii",
										  'repo': "OctoPrint-PrusaSlicerThumbnails", 'current': self._plugin_version,
										  'stable_branch': {'name': "Stable", 'branch': "master",
															'comittish': ["master"]}, 'prerelease_branches': [
				{'name': "Release Candidate", 'branch': "rc", 'comittish': ["rc", "master"]}
			], 'pip': "https://github.com/ThomasToka/OctoPrint-PrusaSlicerThumbnails/archive/refs/heads/E3S1PROFORKBYTT.zip"}}

__plugin_name__ = "E3S1PROFORKBYTTT Thumbnails"
__plugin_pythoncompat__ = ">=2.7,<4"  # python 2 and 3

def __plugin_load__():
	global __plugin_implementation__
	__plugin_implementation__ = E3S1PROFORKBYTTThumbnailsPlugin()

	global __plugin_hooks__
	__plugin_hooks__ = {
		"octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
		"octoprint.filemanager.extension_tree": __plugin_implementation__.get_extension_tree,
		"octoprint.server.http.routes": __plugin_implementation__.route_hook,
		"octoprint.server.api.before_request": __plugin_implementation__.hook_octoprint_server_api_before_request,
		"octoprint.access.permissions": __plugin_implementation__.get_additional_permissions,
	}
