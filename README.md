# SRF Firewall Defense

This project hosts a short python script I used for analysing the Zeek logs provided for the Objective 12 of KringleCon II of the SANS Holiday Hack Challenge in 2019.

Zeek logs to download: https://downloads.elfu.org/http.log.gz

SRF website: srf.elfu.org

## Detection rules

* SQLi: username OR uri OR user_agent contains " ' "
* XSSL: uri OR host contains "<"
* LFI: uri contains "pass"
* Shell: user_agent contains ":;" or "};"

## Usage

```python
python3 parse_logs.py
```

This will output a bunch of IP addresses separated by comma, which can be pasted directly into the FW input field for creating a DENY.
