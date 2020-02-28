# -*- coding: utf-8 -*-
"""
Program: ingest_and_process_ezproxy.py
Author: Nick Paulson, npaulson@umich.edu
Created: 1/17/2020
Last Updated by: Nick Paulson, npaulson@umich.edu
Last Updated: 2/21/2020
Purpose: 1. ingest ezproxy logs from library server and save in LLAP server. 
         2. Parse raw ezproxy logs and import to LLAP SQL Server
Inputs: Configuration files with locations of logs
Outputs: SQL tables
"""
#%%

import pandas as pd
import os
import os.path
import json
import numpy as np
from datetime import datetime
import sqlalchemy

#%%
#set up connection to sql server
#Note: set this string to your connection string to server
engine = sqlalchemy.create_engine("mssql+pyodbc:///?odbc_connect=Driver%3D%7BODBC+Driver+17+for+SQL+Server%7D%3BServer%3DISR-LLAP%3BDatabase%3DLibraryLogs_test%3Buid%3DISR%5C%2Ausername%2A%3Bpwd%3D%2Apassword%2A%3BTrusted_Connection%3Dyes%3B", fast_executemany = True)
conn = engine.connect()

#%%
def ingest_ezproxy(is_production):
    
    '''
    Retrieve library logs from library server and copy to LLAP server
    
    Parameters
    -----------
    is_production: boolean
        Boolean indicating whether script is in testing or production
    
    Returns
    ----------
    None
    '''
    
    #Path to ezproxy server
    libraryLogsDirectory = os.path.join(r"\\ulib-logs.m.storage.umich.edu", "ulib-logs", "archive", "sherry.umdl.umich.edu", "l", "local", "logs", "ezproxy")
    
    #initialize today timestamp
    todayTimestamp = datetime.datetime.now() 
    
    #Log types available in ezproxy server
    logs = [{"log_type": "proxyLogs", "pattern":r"\ezproxy\proxylogs"}, {"log_type": "accessLogs", "pattern" : r"\ezproxy\access.log"}]

    #Loop through log paths in server
    for log in logs:
        
        #Set destination path on LLAP server
        paths = [r"\\isr-llap", "LibraryLogs_RAW", "ezproxy", log['log_type']]
        destinationPath = os.path.join(*paths)
        
        #Set path pattern to search for 
        pattern = log['pattern']
        
        #Check if path exists and create if necessary
        if not os.path.exists(destinationPath):
            os.makedirs(destinationPath)
        
        # Get last edit time of files on server
        # Note: this will change in future updates to more efficiently ingest 
        # files
        edit_time = []
        
        #For file in LLAP server directory
        for root, dirs, files in os.walk(destinationPath):
            
            #Get timestamp from all files
            for name in files:
                file_edit = datetime.datetime.fromtimestamp(os.path.getmtime((os.path.join(root, name))))
                edit_time.append(file_edit)
        
        #Set last edit time to max of all files
        if len(edit_time) > 0:
            lastTimestamp = max(edit_time)
        else:
            lastTimestamp = datetime.datetime.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
            
        #Loop through files in library server and move files if they meet criteria
        for file in os.listdir(libraryLogsDirectory):
            
            #Set file path of files as file plus library server directory
            wholePath = os.path.join(libraryLogsDirectory, file)
            
            #If file meets path pattern criteria set destination path
            if pattern in wholePath:
                currDestPath = destinationPath
                if not os.path.exists(currDestPath):
                    os.makedirs(currDestPath)
                
                #Print destination path
                copyCommand = "copy "+ wholePath + " "+ destinationPath
                
                #Get timestamp from current file on library server directory
                fileTimestamp = datetime.datetime.fromtimestamp(os.path.getmtime(wholePath))
                
                # If file timestamp greater than last file timestamp and file has
                # last been editted more than a day ago, copy file 
                if fileTimestamp > lastTimestamp and fileTimestamp < todayTimestamp - datetime.timedelta(days=1): #check if file has been modified since last time script ran   
                    
                    #if in production copy file
                    if is_production:
                        os.popen(copyCommand) 
                    #if in testing, print copy command and file name
                    else: 
                        print("copy command:   "+copyCommand)
                        print("timeStamp: "+ fileTimestamp.strftime("%Y/%m/%d %H:%M:%S") +" File: "+str(wholePath))

#%%
def list_files(root_directory):
    
    '''
    Return a list of all files in a folder including files in its sub-folder
    
    Parameters
    ----------
    
    directory: string
        File path to directory
    
    Returns
    ---------
    file_paths: list
        List of file paths
    '''
    
    file_paths = []
    for root, directory, files in os.walk(root_directory):
        for name in files:
            file_path = (os.path.join(root, name))
            file_paths.append(file_path)
    return file_paths

#%%
def format_ezproxy(chunk):
    
    '''
    Function to parse ezproxy logs in apache log strings and return dataframes 
    containing valid and invalid logs
    
    Parameters
    ----------
    chunk: Pandas dataframe
        Dataframe with one column containing raw log string
    
    Returns
    ---------
    df_logs: Pandas dataframe
        Dataframe of logs that have been successfully parsed
    df_invalid: Pandas dataframe
        Dataframe of logs that have not been successfully parsed
    '''
    
    #EZproxy logs are stored as apache log strings. Set up regular expression to process logs depending on timestamp of log
    regex_log = r'^(?P<ip_address>\S+) \S+ (?P<username>\S+) \[(?P<click_time>[\w:\/]+\s[+\-]\d{4})\] "(?P<request>.*)?\s?" (?P<http_code>\d{3}|-) (?:\d+|-\s?) (?P<library_session>\S+) (?P<referrer>.+) "?\\?"[^\"]*?"\\?"? (?P<county>.*?|\s) (?P<state>.*?|\s) (?P<city>.*?|\s)(?:\s(?P<ezproxy_session>\S{22}|-))?$'
                
    #Extract fields from log string using regular expression
    df_logs = chunk.log.str.extract(regex_log)
    
    #If a log does not conform to regex format, all values are null. 
    #In valid logs, request can never be null
    #If request is null, log is invalid
    valid = pd.notnull(df_logs.request)
    
    #Split log file into valid and invalid logs
    df_logs = df_logs[valid ==True].copy()
    df_invalid = chunk[valid==False].copy()
        
    #Remove utc offset from time and convert to datetime
    df_logs.click_time = df_logs.click_time.str.extract("([0-9]{2}/[a-zA-Z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}).*")
    df_logs.click_time = pd.to_datetime(df_logs.click_time, format = "%d/%b/%Y:%H:%M:%S")

    #Replace null indicator strings with NaN
    df_logs = df_logs.replace({"-": np.NaN})
    df_logs = df_logs.replace({" ": np.NaN})
    
    #Return dataframe of valid and invalid logs
    return df_logs, df_invalid

#%%
def process_log(file_path, log_type, is_production, format_log):
    
    '''
    Process log file and save cleaned version for later use
    
    Parameters
    ----------
    file_path: string
        File path to log file
    log_type: string
        String containing log type
    is_production: boolean
        Boolean indicator whether script is in testing or production
    format_log: function
        Pointer to function for formatting log type
    '''
    
    #Set globals for processing
    num_of_logs = 0
    num_invalid = 0    
    valid = True
    error = np.NaN
    processing_start_time = datetime.now().replace(microsecond = 0)
    
    #Print log and time to keep track of progress
    print(file_path + ": " + datetime.strftime(processing_start_time, "%m/%d/%Y %H:%M:%S"))
    
    #Try to process log if there is an error, record the error in processing_time table
    try:
    
        #Create chunk reader. Pandas to_sql method can be very memory intensive 
        #and larger chunks may crash computer. Adjust chunk size as need to 
        chunker = pd.read_csv(file_path, header = None, sep = "\n", names = ["log"], encoding = "utf8", chunksize = 1000000)

        for chunk in chunker:
            df_logs, df_invalid = format_log(chunk)
            df_logs['file_path'] = file_path
            df_logs['processing_start_time'] = processing_start_time
            num_of_logs += len(df_logs)
            num_invalid += len(df_invalid)
            df_invalid['processing_start_time'] = processing_start_time
            df_invalid['log_type'] = log_type
            df_invalid['file_path'] = file_path
            

            #Import logs into sql
            #Note: this section will be updated to more efficiently store logs
            #in the future
            if is_production:
                df_logs.to_sql(log_type, engine, if_exists = "append", index = False)
                df_invalid.to_sql(f"invalid_logs", engine, if_exists = "append", index = False)
            else:
                print(df_logs)
                print(df_invalid)
            
        #Cleanup any old invalid log records
        if file_path in invalid_files:
            conn.execute(f"""Delete from processing_time where
                             file_path = '{file_path}' and valid = 0""")
                             
    #Delete all processed logs if keyboard interrupt occurs then raise error
    except KeyboardInterrupt:
        conn.execute(f"""Delete from {log_type}
                         where file_path = '{file_path}'""")
        conn.execute(f"""Delete from invalid_logs
                         where file_path = '{file_path}'""")
        raise
    
    #If script fails, log error and delete logs from file
    #processed prior to failure
    except Exception as e:
        
        valid = False
        print(e)
        error = str(e)
        
        #Log files are processed in 1000000 log chunks to ensure there is enough 
        #memory available. If log fails at any point in processing, delete all logs 
        #previously processed from that file
        conn.execute(f"""Delete from {log_type}
                         where file_path = '{file_path}'""")
        conn.execute(f"""Delete from invalid_logs 
                         where file_path = '{file_path}'""")
    
    #Get end time for processing
    processing_end_time = datetime.now().replace(microsecond = 0)
    
    #Create processing record
    df_processing_record = pd.DataFrame({"file_path": [file_path], 
                                         "log_type": [log_type], 
                                         "processing_start_time": [processing_start_time], 
                                         "processing_end_time": [processing_end_time],
                                         "valid": [valid],
                                         "num_of_logs": [num_of_logs],
                                         "num_invalid": [num_invalid],
                                         "error": [error]
                                         })
    
    #If script is in production import to sql.
    #Else print record
    if is_production:      
        #Note: this section will be updated to more efficiently store logs 
        #in the future
        #Create processing record in SQL
        df_processing_record.to_sql(f"processing_time", engine, if_exists = "append", index = False)
    else:
       print(df_processing_record)

#%%
def get_processed_files():
    
    '''
    Get list of processed files from sql server
    
    Parameters
    -----------
    None
    
    Returns
    ----------
    processed_files: set
        Set containing all currently processed files
    
    '''
    
    sql_valid = conn.execute(f"""Select distinct file_path from processing_time where valid = 1""")
    processed_files = set([rowproxy.values()[0] for rowproxy in sql_valid])  
    return processed_files

#%%
def get_invalid_files():
    
    '''
    Get list of invalid files from sql server
    
    Parameters
    -----------
    None
    
    Returns
    ----------
    invalid_files: set
        Set containing all files that have previously raised error 
    '''
    
    sql_invalid = conn.execute(f"""Select distinct file_path from processing_time where valid = 0""")
    invalid_files = set([rowproxy.values()[0] for rowproxy in sql_invalid])
    return invalid_files

#%%

#Ingest new ezproxy files 
ingest_ezproxy(isproduction = False)

#%%
#Log configuration file
#Note: set this path to location of appropriate CONFIG_FILE.
CONFIG_FILE = r"\\src-hess\data\/LLAP/Documentation_LibFellows/Nick/LLAP_Advisory_030620/CONFIG_FILE.json"
with open(CONFIG_FILE, "r") as f:
    config = json.loads(f.read())

#Get processed files and invalid files from SQL
#Note: this section will change to more efficiently work through stored logs
processed_files = get_processed_files()
invalid_files = get_invalid_files()

#%%
#Process each type of log in the configuration file
#Configuration file contains the log type and log path for each library log
# Note: in full script for all logs at Michigan this is required. In current
# script config file has a single log, ezproxy
for log_config in config:
    
    #Set path and log type
    #Note: in full script for all logs at Michigan this is required
    open_path = log_config['log_directory']
    log_type = log_config['log_type']

    #List all files in directory
    files = list_files(open_path)
    
    #Set format_log to appropriate function.
    #Note: in full script for all logs at Michigan this is required
    format_log = format_ezproxy
    
    #go through each file in the folder.
    for file_path in files:
        #Skip if log exists
        #Note: this section will change to more efficiently work through stored
        #logs in the future
        if file_path in processed_files:
            print("Existing log:" + file_path)
            pass
        else:           
            #Process log file
            process_log(file_path, log_type, format_log)

