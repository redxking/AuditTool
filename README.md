Written by Angelis Pseftis
---

# Cisco Configuration Audit Script

This Python script is a tool for auditing Cisco network device configurations. It verifies whether certain security rules, specified in STIG (Security Technical Implementation Guide) YAML files, are being followed in the given configuration file.

## Dependencies

- Python 3.x
- `ciscoconfparse`: A library for parsing Cisco configurations. Can be installed via pip: `pip install ciscoconfparse`.
- `PyYAML`: A library for parsing YAML files. Can be installed via pip: `pip install PyYAML`.

## Usage

To run the script:

```
python script_name.py config_file [--stig STIG] [--os_type OS_TYPE] [-v VERBOSITY] [-f]
```

where:

- `config_file` is the configuration text file to scan.
- `--stig` (optional) is the STIG to be used for the audit.
- `--os_type` (optional) is the operating system type: `ios`, `xr`, `nxos`, or `asa`.
- `-v` or `--verbosity` (optional) controls the verbosity of output: `0` for brief, `1` for details, `2` for CSV rows. Default is `0`.
- `-f` or `--failonly` (optional) specifies to print failures only.

For example:

```
python script_name.py example_config.txt --stig example_stig --os_type ios -v 1
```

## Log Files

The script logs information to a file named `audit.log`. This file includes timestamps for when certain events occur during the execution of the script, such as errors while parsing the configuration file or loading YAML data.

## Exit Codes

The script returns the number of failed rules as its exit code.

---

