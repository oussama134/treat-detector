import csv
import pandas as pd
modelpath = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\raw\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
path=pd.read_csv(modelpath)
print(path.columns.tolist())
