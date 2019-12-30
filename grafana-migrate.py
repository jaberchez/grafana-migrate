#! /usr/bin/python3

###################################################################################################################
# Descripcion: Script to migrate Grafana objects (folders, dashboards...) from one Grafana to another
###################################################################################################################

# Imports
#------------------------------------------------------------------------------------------------------------------
import os
import sys
import re
import signal
import requests
import json
import yaml
import getopt
import base64
import string
import random
import logging
#------------------------------------------------------------------------------------------------------------------

# Variables and constants
#------------------------------------------------------------------------------------------------------------------
DEBUG_LEVEL          = 'DEBUG'
INFO_LEVEL           = 'INFO'
WARNING_LEVEL        = 'WARNING'
ERROR_LEVEL          = 'ERROR'
CRITICAL_LEVEL       = 'CRITICAL'
DEFAULT_LOG_LEVEL    = INFO_LEVEL

DEFAULT_HTTP_HEADERS = {
   'Accept': 'application/json',
   'Content-Type': 'application/json',
}

grafana_url_src      = None
grafana_url_dest     = None

file_conf            = None
conf                 = {}
log_level            = DEFAULT_LOG_LEVEL
app_debug            = False
#------------------------------------------------------------------------------------------------------------------

# Functions
#==================================================================================================================
# Description: Show how to usage this script
# Parameters:  None
# Return:      Nothing, finish the script

def usage():
   log(INFO_LEVEL, 
       "Usage: {} [-h|--help] [-d|--debug] <-f|--file file_conf.yaml>".format(os.path.basename(sys.argv[0])))
   sys.exit(1)
#==================================================================================================================

#==================================================================================================================
# Description: Main
# Parameters:  None
# Return:      Nothing, if there is a problem finish the script

def main():
   global conf

   load_file_conf()

   if 'datasources' in conf['migrate'] and len(conf['migrate']['datasources']) > 0:
      migrate_datasources()

   if 'folders' in conf['migrate'] and len(conf['migrate']['folders']) > 0:
      migrate_folders()

   if 'dashboards' in conf['migrate'] and len(conf['migrate']['dashboards']) > 0:
      migrate_dashboards()

   if 'users' in conf['migrate'] and len(conf['migrate']['users']) > 0:
      migrate_users()
#==================================================================================================================

#==================================================================================================================
# Description: Migrate folders
# Parameters:  None
# Return:      Nothing, if there is a problem finish the script

def migrate_folders():
   global DEFAULT_HTTP_HEADERS
   global conf

   if app_debug:
      total = 0

      #log(DEBUG_LEVEL, "Starting migrating folders")

   check_api_keys()

   headers_src  = DEFAULT_HTTP_HEADERS.copy()
   headers_dest = DEFAULT_HTTP_HEADERS.copy()
      
   headers_src['Authorization']  = 'Bearer {}'.format(conf['global']['apiKeySrc'])
   headers_dest['Authorization'] = 'Bearer {}'.format(conf['global']['apiKeyDest'])
   
   folders_src    = []
   folders_dest   = []

   try:
      # Get folders from source 
      response = requests.get('{}/api/folders'.format(grafana_url_src), headers=headers_src)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting source folders: {}".format(response.text))
         sys.exit(1)

      folders_src  = response.json()

      # Get folders from destination
      response     = requests.get('{}/api/folders'.format(grafana_url_dest), headers=headers_dest)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting destination folders {}".format(response.text))
         sys.exit(1)

      folders_dest = response.json()
   except Exception as e:
      log(ERROR_LEVEL, "Migrate folders: {}".format(e))
      sys.exit(1)

   for folder_src in folders_src:
      folder_exists        = False
      candidate_to_migrate = False

      # Check if this folder is candidate to migrate
      for f in conf['migrate']['folders']:
         if f == 'all' or folder_src['title'] == f:
            candidate_to_migrate = True
            break

      if not candidate_to_migrate:
         continue

      for folder_dest in folders_dest:
         if folder_src['title'] == folder_dest['title']:
            folder_exists  = True
            break

      if not folder_exists:
         # Create folder
         try:
            # Get details about the source folder 
            response = requests.get('{}/api/folders/{}'.format(grafana_url_src, folder_src['uid']), 
                                                               headers=headers_src)
            if int(response.status_code) != 200:
               log(ERROR_LEVEL, "Getting details source folder: {}".format(r.text))
               sys.exit(1)

            data    = response.json()

            payload = {
               'title': '{}'.format(data['title']),
               'canSave': '{}'.format(data['canSave']),
               'canEdit': '{}'.format(data['canEdit']),
               'hasAcl': '{}'.format(data['hasAcl']),
               'canAdmin': '{}'.format(data['canAdmin'])
            }

            # Check if we have to create this folder
            if 'all' in conf['migrate']['folders'] or folder_src['title'] in conf['migrate']['folders']:
               # Create folder
               payload = json.dumps(payload).encode("utf-8")
               r       = requests.post("{}/api/folders".format(grafana_url_dest), headers=headers_dest, data=payload)

               if int(r.status_code) != 200:
                  log(ERROR_LEVEL, 'Creating folder "{}": {}'.format(data['title'],r.text))
                  sys.exit(1)

               if app_debug:
                  log(DEBUG_LEVEL, 'Folder "{}" migrated successfully'.format(folder_src['title']))
                  total += 1
         except Exception as e:
            log(ERROR_LEVEL, "Creating folder: {}".format(e))
            sys.exit(1)

   if app_debug:
      log(DEBUG_LEVEL, "Total folders migrated: {}".format(total))
#==================================================================================================================

#==================================================================================================================
# Description: Migrate dashboards
# Parameters:  None
# Return:      Nothing, if there is a problem finish the script

def migrate_dashboards():
   global DEFAULT_HTTP_HEADERS
   global conf

   if app_debug:
      total = 0

      #log(DEBUG_LEVEL, "Starting migrating dashboards")

   check_api_keys()

   headers_src  = DEFAULT_HTTP_HEADERS.copy()
   headers_dest = DEFAULT_HTTP_HEADERS.copy()
      
   headers_src['Authorization']  = 'Bearer {}'.format(conf['global']['apiKeySrc'])
   headers_dest['Authorization'] = 'Bearer {}'.format(conf['global']['apiKeyDest'])

   dashboards_src    = []
   dashboards_dest   = []

   try:
      # Get all dashboards from source
      response = requests.get('{}/api/search?query=&type=dash-db'.format(grafana_url_src), headers=headers_src)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting source dashboards: {}".format(response.text))
         sys.exit(1)

      dashboards_src = response.json()

      # Get all dashboards from destination
      response = requests.get('{}/api/search?query=&type=dash-db'.format(grafana_url_dest), headers=headers_dest)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting destination dashboards: {}".format(response.text))
         sys.exit(1)

      dashboards_dest = response.json()
   except Exception as e:
      log(ERROR_LEVEL, "Getting dashboards: {}".format(e))
      sys.exit(1)

   for dashboard_src in dashboards_src:
      dashboard_exists     = False
      create_dashboard     = False
      candidate_to_migrate = False
      overwrite            = False
      folderId             = 0  # Default folderId for "General" folder

      # Check if this dashboard is candidate to migrate
      # Notice: If we set "all" ignore the rest of the list (if there is something)
      for dash in conf['migrate']['dashboards']:
         if not 'folderTitle' in dashboard_src:
            dashboard_src['folderTitle'] = 'General'

         if dash['name'] == 'all' or (dashboard_src['title']       == dash['name'] and \
                                      dashboard_src['folderTitle'] == dash['folder']):
            candidate_to_migrate = True

            if 'overwrite' in dash:
               overwrite = dash['overwrite']
            else:
               overwrite = False

            break

      if not candidate_to_migrate:
         continue

      # Notice: This dashboard is candidate to migrate. We migrate it if
      #         it does not exist or "overwrite: true" is configured
      #
      # Check if dashboard already exists in destination
      # Notice: We check if the dashboard exists and belongs to the
      #         same folder
      for dashboard_dest in dashboards_dest:
         if (dashboard_src['title']       == dashboard_dest['title']) and \
            (dashboard_src['folderTitle'] == dashboard_dest['folderTitle']):
            dashboard_exists  = True
            break

      if dashboard_exists:
         if overwrite:
            # Dashboard exists but we must overwrite it
            create_dashboard = True
      else:
         # Dashboard does not exist, we create it 
         create_dashboard = True

      if create_dashboard:
         # Create dashboard
         try:
            # Get details of the source dashboard 
            response = requests.get('{}/api/dashboards/uid/{}'.format(grafana_url_src, dashboard_src['uid']), 
                                    headers=headers_src)

            if int(response.status_code) != 200:
               log(ERROR_LEVEL, 'Getting details source dashboard: {}'.format(response.text))
               sys.exit(1)

            details_dash_src = response.json()

            # Get destination folders to know de folderId where this dashboard should be stored
            response = requests.get('{}/api/folders'.format(grafana_url_dest), headers=headers_dest)

            if int(response.status_code) != 200:
               log(ERROR_LEVEL, "Getting destination folder: {}".format(response.text))
               sys.exit(1)

            folders_dest = response.json()

            for folder in folders_dest:
               if details_dash_src['meta']['folderTitle'] == folder['title']:
                  folderId = int(folder['id'])
                  break

            del details_dash_src['dashboard']['id']
            del details_dash_src['dashboard']['uid']
            del details_dash_src['dashboard']['version']
            del details_dash_src['meta']

            payload = {
               'dashboard': details_dash_src['dashboard'],
               "folderId": folderId,
               "overwrite": overwrite
            }

            payload = json.dumps(payload).encode("utf-8")
            r       = requests.post("{}/api/dashboards/db".format(grafana_url_dest), 
                                    headers=headers_dest, data=payload)

            if int(r.status_code) != 200:
               log(ERROR_LEVEL, "Creating dashboard: {}".format(r.text))
               sys.exit(1)

            if app_debug:
               log(DEBUG_LEVEL, 
                  'Dashboard "{}" migrated successfully in folder "{}"'.format(dashboard_src['title'], 
                                                                   dashboard_src['folderTitle']))
               total += 1
         except Exception as e:
            log(ERROR_LEVEL, "Migrating dashboards: {}".format(e))
            sys.exit(1)

   if app_debug:
      log(DEBUG_LEVEL, "Total dashboards migrated: {}".format(total))
#==================================================================================================================

#==================================================================================================================
# Description: Migrate users
# Parameters:  None
# Return:      Nothing, if there is a problem finish the script

def migrate_users():
   global DEFAULT_HTTP_HEADERS
   global conf

   if app_debug:
      total = 0

      #log(DEBUG_LEVEL, "Starting migrating users")

   check_auth_basic()

   headers_src  = DEFAULT_HTTP_HEADERS.copy()
   headers_dest = DEFAULT_HTTP_HEADERS.copy()
      
   # Basic Authorization
   headers_src['Authorization']  = 'Basic {}'.format(conf['global']['adminAuthSrc'])
   headers_dest['Authorization'] = 'Basic {}'.format(conf['global']['adminAuthDest'])

   users_src   = []
   users_dest  = []

   try:
      # Get all users (from source and destination)
      response   = requests.get('{}/api/users'.format(grafana_url_src), headers=headers_src)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting source users: {}".format(response.text))
         sys.exit(1)

      users_src = response.json()

      response  = requests.get('{}/api/users'.format(grafana_url_dest), headers=headers_dest)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting destination users: {}".format(response.text))
         sys.exit(1)

      users_dest = response.json()
   except Exception as e:
      log(ERROR_LEVEL, "Getting users: {}".format(e))
      sys.exit(1)

   for user_src in users_src:
      user_exists          = False
      candidate_to_migrate = False

      # We don't migrate admin user
      if user_src['login'] == 'admin':
         continue

      # Check if this user is candidate to migrate
      for u in conf['migrate']['users']:
         if u == 'all' or user_src['login'] == u:
            candidate_to_migrate = True
            break

      if not candidate_to_migrate:
         continue

      for user_dest in users_dest:
         if user_src['login'] == user_dest['login']:
            user_exists = True
            break

      if not user_exists:
         # Create user
         try:
            payload = {
               'name': '{}'.format(user_src['name']),
               'login': '{}'.format(user_src['login']),
               'email': '{}'.format(user_src['email']),
               'password': generate_password()
            }
    
            # Notice:  The URL to create users is diferent. We have to
            #          use the authentication in the own url. Since we alreay have
            #          the user and password in base64 we reuse them
            # Example: http://user:pass@server:port/api/admin/users
            http_auth = base64.decodestring(conf['global']['adminAuthDest'].encode('utf-8'))
            pos       = grafana_url_dest.find('://')
            http_url  = grafana_url_dest[:pos + 3] + http_auth.decode('utf-8') + '@' + grafana_url_dest[pos + 3:]

            payload   = json.dumps(payload).encode("utf-8")
            r         = requests.post("{}/api/admin/users".format(http_url), headers=headers_dest, data=payload)

            if int(r.status_code) != 200:
               log(ERROR_LEVEL, "Creating user: {}".format(r.text))
               sys.exit(1)

            # Get the newly created user id because we need it to modify permissions
            r = requests.get('{}/api/users/lookup?loginOrEmail={}'.format(grafana_url_dest, user_src['login']), 
                             headers=headers_dest)

            if int(r.status_code) != 200:
               log(ERROR_LEVEL, "Getting new created user: {}".format(r.text))
               sys.exit(1)

            user = r.json()

            # We already created the user, now we have to modify some permisions
            payload = {
               'isAdmin': user_src['isAdmin'],
               'isDisabled': user_src['isDisabled'],
               'authLabels': user_src['authLabels']
            }
    
            payload   = json.dumps(payload).encode("utf-8")
            r         = requests.put("{}/api/admin/users/{}/permissions".format(http_url, user['id']), 
                                     headers=headers_dest, data=payload)

            if int(r.status_code) != 200:
               log(ERROR_LEVEL, "Updating user permissions: {}".format(r.text))
               sys.exit(1)

            if app_debug:
               log(DEBUG_LEVEL, 'User "{}" migrated successfully'.format(user_src['login']))
               total += 1
         except Exception as e:
            log(ERROR_LEVEL, "Migrating users: {}".format(e))
            sys.exit(1)

   if app_debug:
      log(DEBUG_LEVEL, "Total users migrated: {}".format(total))
#==================================================================================================================

#==================================================================================================================
# Description: Migrate datasources
# Parameters:  None
# Return:      Nothing, if there is a problem finish the script

def migrate_datasources():
   global DEFAULT_HTTP_HEADERS
   global conf

   if app_debug:
      total = 0

   check_api_keys()

   headers_src  = DEFAULT_HTTP_HEADERS.copy()
   headers_dest = DEFAULT_HTTP_HEADERS.copy()

   headers_src['Authorization']  = 'Bearer {}'.format(conf['global']['apiKeySrc'])
   headers_dest['Authorization'] = 'Bearer {}'.format(conf['global']['apiKeyDest'])

   datasources_src    = []
   datasources_dest   = []

   try:
      # Get datasource from source
      response = requests.get('{}/api/datasources'.format(grafana_url_src), headers=headers_src)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting source datasources: {}".format(response.text))
         sys.exit(1)

      datasources_src  = response.json()

      # Get datasource from destination
      response     = requests.get('{}/api/datasources'.format(grafana_url_dest), headers=headers_dest)

      if int(response.status_code) != 200:
         log(ERROR_LEVEL, "Getting destination datasources: {}".format(response.text))
         sys.exit(1)

      datasources_dest = response.json()
   except Exception as e:
      log(ERROR_LEVEL, "Migrate datasources: {}".format(e))
      sys.exit(1)

   for datasource_src in datasources_src:
      datasource_exists    = False
      candidate_to_migrate = False

      # Check if this datasource is candidate to migrate
      for d in conf['migrate']['datasources']:
         if d == 'all' or datasource_src['name']  == d: 
            candidate_to_migrate = True
            break

      if not candidate_to_migrate:
         continue

      for datasource_dest in datasources_dest:
         if datasource_src['name'] == datasource_dest['name']:
            datasource_exists  = True
            break

      if not datasource_exists:
         # Create Datasource
         try:
            payload = datasource_src

            del payload['id']
            del payload['orgId']

            payload = json.dumps(payload).encode("utf-8")
            r       = requests.post("{}/api/datasources".format(grafana_url_dest), headers=headers_dest, data=payload)

            if int(r.status_code) != 200:
               log(ERROR_LEVEL, "Creating datasource: {}".format(r.text))
               sys.exit(1)

            if app_debug:
               log(DEBUG_LEVEL, 'Datasource "{}" migrated successfully'.format(datasource_src['name']))
               total += 1
         except Exception as e:
            log(ERROR_LEVEL, "Migrating datasources: {}".format(e))
            sys.exit(1)

   if app_debug:
      log(DEBUG_LEVEL, "Total datasources migrated: {}".format(total))
#==================================================================================================================

#==================================================================================================================
# Description: Handle signals
# Parameters:  Signal and frame of the object
# Return:      Nothing, just exit

def signal_handler(sig, frame):
   name_signal = ''

   if sig == 2:
      name_signal = "SIGINT"
   elif sig == 15:
      name_signal = "SIGTERM"
   else:
      name_signal = "UNKNOWN"

   print("\nCatch signal: " + name_signal)
   sys.exit(0)
#==================================================================================================================

#==================================================================================================================
# Description: Load file conf
# Parameters:  None
# Return:      Nothing, if there is any problem finish the script

def load_file_conf():
   global file_conf
   global conf
   global grafana_url_src
   global grafana_url_dest

   with open(file_conf) as stream:
      try:
         conf = yaml.load(stream, Loader=yaml.FullLoader)
      except yaml.YAMLError as ex:
         log(ERROR_LEVEL, "Load file conf: {}".format(ex))
         sys.exit(1)

   if not 'global' in conf:
      log(ERROR_LEVEL, "Not global section in \"{}\"".format(file_conf))
      sys.exit(1)

   if not 'migrate' in conf:
      log(ERROR_LEVEL, "Not migrate section in \"{}\"".format(file_conf))
      sys.exit(1)

   # Check if the sensitive data in global section is configured as 
   # environment variables
   admin_auth_src   = os.environ.get('GLOBAl_ADMIN_AUTH_SRC')
   admin_auth_dest  = os.environ.get('GLOBAl_ADMIN_AUTH_DEST')
   api_key_src      = os.environ.get('GLOBAl_API_KEY_SRC')
   api_key_dest     = os.environ.get('GLOBAL_API_KEY_DEST')

   if admin_auth_src != None:
      conf['global']['adminAuthSrc'] = admin_auth_src

   if admin_auth_dest != None:
      conf['global']['adminAuthDest'] = admin_auth_dest

   if api_key_src != None:
      conf['global']['apiKeySrc'] = api_key_src

   if api_key_dest != None:
      conf['global']['apiKeyDest'] = api_key_dest

   if 'urlGrafanaSrc' in conf['global']:
      if len(conf['global']['urlGrafanaSrc']) == 0:
         log(ERROR_LEVEL, "urlGrafanaSrc is empty")
         sys.exit(1)
      elif not re.match(r'^http://', str(conf['global']['urlGrafanaSrc'])):
         log(ERROR_LEVEL, "URL incorrect in urlGrafanaSrc")
         sys.exit(1)
      else:
         grafana_url_src = conf['global']['urlGrafanaSrc']
   else:
      log(ERROR_LEVEL, "urlGrafanaSrc not found in global section")
      sys.exit(1)

   if 'urlGrafanaDest' in conf['global']:
      if len(conf['global']['urlGrafanaDest']) == 0:
         log(ERROR_LEVEL, "urlGrafanaDest is empty")
         sys.exit(1)
      elif not re.match(r'^http://', str(conf['global']['urlGrafanaDest'])):
         log(ERROR_LEVEL, "URL incorrect in urlGrafanaDest")
         sys.exit(1)
      else:
         grafana_url_dest = conf['global']['urlGrafanaDest']
   else:
      log(ERROR_LEVEL, "urlGrafanaDest not found in global section")
      sys.exit(1)

   if 'folders' in conf['migrate']:
      for f in conf['migrate']['folders']:
         if f == 'all':
            # If the configuration is "all", we ensure that is the only element of the list to
            # avoid any problem
            conf['migrate']['folders'].clear()
            conf['migrate']['folders'].append('all')

            break

   if 'dashboards' in conf['migrate']:
      for d in conf['migrate']['dashboards']:
         if not 'name' in d:
            log(ERROR_LEVEL, "name not found in dashboard")
            sys.exit(1)

         if d['name'] == 'all':
            overwrite = False

            # Like in folders, if the configuration is "all", we ensure that is the only element of the list
            # to avoid any problem
            if 'overwrite' in d:
               overwrite = d['overwrite']

            conf['migrate']['dashboards'].clear()
            conf['migrate']['dashboards'].append({'name': 'all', 'overwrite': overwrite})

            break

   if 'users' in conf['migrate']:
      for u in conf['migrate']['users']:
         if u == 'all':
            conf['migrate']['users'].clear()
            conf['migrate']['users'].append('all')

            break

   if 'datasources' in conf['migrate']:
      for d in conf['migrate']['datasources']:
         if d == 'all':
            conf['migrate']['datasources'].clear()
            conf['migrate']['datasources'].append('all')

            break
#==================================================================================================================

#==================================================================================================================
# Description: Sanity check for global apiKey* directives
# Parameters:  None
# Return:      Nothing, if there is any problem finish the script

def check_api_keys():
   global conf

   if 'apiKeySrc' in conf['global']:
      if len(conf['global']['apiKeySrc']) == 0:
         log(ERROR_LEVEL, "apiKeySrc is empty")
         sys.exit(1)
   else:
      log(ERROR_LEVEL, "apiKeySrc not found in global section")
      sys.exit(1)

   if 'apiKeyDest' in conf['global']:
      if len(conf['global']['apiKeyDest']) == 0:
         log(ERROR_LEVEL, "apiKeyDest is empty")
         sys.exit(1)
   else:
      log(ERROR_LEVEL, "apiKeyDest not found in global section")
      sys.exit(1)

#==================================================================================================================

#==================================================================================================================
# Description: Sanity check for global authBasic* directives
# Parameters:  None
# Return:      Nothing, if there is any problem finish the script

def check_auth_basic():
   global conf

   if 'adminAuthSrc' in conf['global']:
      if len(conf['global']['adminAuthSrc']) == 0:
         log(ERROR_LEVEL, "adminAuthSrc is empty")
         sys.exit(1)
   else:
      log(ERROR_LEVEL, "adminAuthSrc not found in global section")
      sys.exit(1)

   if 'adminAuthDest' in conf['global']:
      if len(conf['global']['adminAuthDest']) == 0:
         log(ERROR_LEVEL, "adminAuthDest is empty")
         sys.exit(1)
   else:
      log(ERROR_LEVEL, "adminAuthDest not found in global section")
      sys.exit(1)

#==================================================================================================================

#==================================================================================================================
# Description: Generate random password
# Parameters:  Size of the password and chars
# Return:      The password

#def generate_password(size=10, chars=string.ascii_uppercase + string.digits + string.punctuation): 
def generate_password(size=10, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits): 
   return ''.join(random.choice(chars) for _ in range(size))
#==================================================================================================================

#==================================================================================================================
# Description: Print message
# Parameters:  Level and message
# Return:      Nothing
#
# Sort:
#    DEBUG
#    INFO
#    WARNING
#    ERROR
#    CRITICAL

def log(level, msg):
   global log_level

   all_log_levels = (DEBUG_LEVEL, INFO_LEVEL, WARNING_LEVEL, ERROR_LEVEL, CRITICAL_LEVEL)
   log_levels     = []
   pos            = 0

   switcher = {
      DEBUG_LEVEL:    logging.debug,
      INFO_LEVEL:     logging.info,
      WARNING_LEVEL:  logging.warning,
      ERROR_LEVEL:    logging.error,
      CRITICAL_LEVEL: logging.critical
   }

   # Get the function to run
   func = switcher.get(level)

   # Create a new list only with the levels we can use, established in LOG_LEVEL
   # environment variable
   for i in range(0, len(all_log_levels)):
      if log_level == all_log_levels[i]:
         pos = i
         break

   if pos + 1 == len(all_log_levels):
      # Last element, the only one
      log_levels = all_log_levels[pos]
   else:
      log_levels = all_log_levels[pos:]

   # Check if we have to run the function
   # Notice: We run the function if LOG_LEVEL is the same or below in terms of sorting
   if level in log_levels:
      # Run
      func("{}".format(msg))
#==================================================================================================================

# Main
#******************************************************************************************************************
if __name__ == '__main__':
   # Catch de signals
   signal.signal(signal.SIGTERM, signal_handler)
   signal.signal(signal.SIGINT,  signal_handler)

   # Logging format
   logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] - %(message)s')

   logging.getLogger("urllib3").setLevel(logging.WARNING)

   log_level = os.environ.get('LOG_LEVEL')

   if log_level == None:
      log_level = DEFAULT_LOG_LEVEL
   elif str(log_level).upper() != DEBUG_LEVEL    and \
        str(log_level).upper() != INFO_LEVEL     and \
        str(log_level).upper() != WARNING_LEVEL  and \
        str(log_level).upper() != CRITICAL_LEVEL and \
        str(log_level).upper() != ERROR_LEVEL:
      log_level = DEFAULT_LOG_LEVEL
   else:
      log_level = log_level.upper()

   # Get and parse arguments
   try:
      opts, args = getopt.getopt(sys.argv[1:],"hdf:", ["help", "debug", "file="])
   except getopt.GetoptError:
      usage()

   for opt, arg in opts:
      if opt in ("-h", "--help"):
         usage()
      elif opt in ("-f", "--file"):
         file_conf = arg
      elif opt in ("-d", "--debug"):
         log_level = DEBUG_LEVEL
         app_debug = True

   if file_conf == None:
      usage()
   elif not os.path.isfile(file_conf):
      log(CRITICAL_LEVEL, "File \"{}\" does not exist".format(file_conf))
      sys.exit(1)
   else:
      statinfo = os.stat(file_conf)

      if statinfo.st_size == 0:
         log(ERROR_LEVEL, "File \"{}\" is empty".format(file_conf))
         sys.exit(1)

   main()
#******************************************************************************************************************
