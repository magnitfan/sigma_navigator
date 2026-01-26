### Usage

```bash
python sigma_navigator.py -r /path/to/sigma/rules -o output_filename.json

# Custom layer name
python sigma_navigator.py -r /path/to/rules -o navigator_layer.json -n "My Sigma Coverage"
```

### Arguments

```
-r, --repo-path PATH    Local Sigma repo path (required)
-o, --output PATH       Output Navigation layer file name and path
-n, --name NAME         Navigator layer name
-v, --verbose           Verbose (log output)
```
