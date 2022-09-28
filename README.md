![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity (AKA FC) is an infrastructure solution for serverless functions signing and verification. This solution is combined from a cli tool and a cloud specific infrastructure for validation. The solution is suitable for a CI/CD process where a code/image of serverless functions can be signed and uploaded before the function is created in the cloud repository.

## How it works

![Untitled Diagram(1) drawio (1)](https://user-images.githubusercontent.com/109651023/189673319-5c66fb32-98f5-430c-a01f-4823ab51fc98.png)

* Deploy FunctionClarity infrastructure (one time operation) which will result in FunctionClarity ecosystem deployed in the user's cloud account
* Using the FunctionClarity cli, run code/image signing on user's environment - at this phase the code/image signature is uploaded to the cloud
* Deploy the serverless function using the signed code/image content from the previous step
* Verifier lambda is triggered upon create-function/update-function code events and performs the following:
  * Fetch the verified function code
  * Analyse the code image/zip
  * Check whether it is signed by FunctionClarity and act accordingly:
    * Detect - marks the function with the verification results
    * Block - block the function from running in case its not verified
    * Notify - send notification to queue
---

**NOTE**:
At the moment only AWS cloud provider is supported, additional cloud providers will be added over time
  
---

## Install FuctionClarity
<TBD>

## Quick start
We'll be using an AWS account, and show how to:
* Initialize and deploy FunctionClarity
* Sign and upload Serverless functions' code
* create new AWS functions
* Check function verification
  * From the cloud account
  * From FunctionClarity command line

### Initialize and deploy FunctionClarity
The command prompts the user to enter information regarding the installation of FunctionClarity.
When this command will finish to run, FunctionClarity will be deployed to your AWS account and a configuration file will be created locally under ~/.fc, the default values for the sign/verify commands will be taken from this config file unless flags are supplied.
```shell
./function-clarity init AWS
enter Access Key: ********
enter Secret Key: ********
enter region: 
enter default bucket (you can leave empty and a bucket with name functionclarity will be created):
select post verification action : (1) for detect; (2) for block; leave empty for no post verification action to perform: 1
is there existing trail in CloudTrail which you would like to use? (if no, please press enter): 
do you want to work in keyless mode (y/n): n
enter path to custom public key for code signing? (if you want us to generate key pair, please press enter): 
Enter password for private key:
Enter password for private key again:
File cosign.key already exists. Overwrite (y/n)? y

Private key written to cosign.key
Public key written to cosign.pub
deployment finished successfully
```

### Sign code
The command below will sign a folder containing code and upload it to the user's cloud account

```shell
./function-clarity sign AWS code /sample-code-verified-folder

using config file: /Users/john/.fc
Enter password for private key:
MEYCIQDskDWwLEURdALycGH/ntCRjA5G74yJ/qeSDzHTQSRY8gIhALE6Z5XW/iyjz++rzrdhzskPwfwW2gAMjK1H9lCXOGom
Code uploaded successfully
```
### Deploy function or update function code
Use AWS cli to deploy lambda or update lambda code
### Verify function code
If you completed "init and deployment" step a verifier function runs in your cloud account and handles CreateFunction/UpdateFunctionCode events, after several minutes your lambda function, in case you chose detect action for "post verification action", will be tagged with FunctionClarity message that the function is verified:

![image](https://user-images.githubusercontent.com/109651023/189880644-bed91413-a81c-4b03-b6f8-00ebea6606a0.png)

You can also use the cli to perform manual verification of a function:
```shell
./function-clarity verify aws funcclarity-test-signed --function-region=us-east-2
using config file: /Users/john/.fc
Verified OK
```

## Advanced usage
FunctionClarity includes several features, we will elaborate on the commands and its usage.
FunctionClarity leverages [cosign](https://github.com/sigstore/cosign) for signing and verifying code, we support key-pair and keyless signing techniques.

### Init command detailed usage
#### AWS
| Input | Description |
| --- | --- |
| access key | AWS access key |
| secret key | AWS secret key |
| region | region to deploy FunctionClarity |
| default bucket | bucket to deploy code signatures and FunctionClarity verifier lambda code for the deployment |
| post verification action | action to perform upon validation results (detect, block or leave empty for no action to perform) |
| sns arn | in case you would like to notify to an sns queue in case function is not verified |
| CloudTrail | cloud trail to use, can be empty and a new trail will be created |
| keyless mode (y/n) | select whether you would like to work in keyless mode |
| public key for code signing | path to public key to use when verifying functions, can leave empty and a key-pair will be created |
| privte key for code signing | in case a public key path was entered, supply the corresponding private key path |


### Sign command detailed usage
FunctionClarity supports signing of code from local folders and images.
When signing images, make sure you are logged in to the docker repository where your images deployed.

---

**NOTE**:
In case a default config file exists (under ~/.fc) it will be used, if a custom config file flag is presented it will be used, if flags are presented that will take precedence.

---
#### AWS
For code signing use the command:
```shell
function-clarity sign aws code <folder to sign> --flags (optional if you have configuration file)
```
For image singing use the command:
```shell
function-clarity sign aws image <image url> --flags (optional if you have configuration file)
```
below is the optional flags that the command uses.
| flag | Description |
| --- | --- |
| access key | AWS access key |
| secret key | AWS secret key |
| region | region to deploy signature (relevant only for code signing) |
| bucket | bucket to deploy code signature (relevant only for code signing)|
| privatekey | key to sign code with |


### Verify command detailed usage

---

**NOTE**:
In case a default config file exists (under ~/.fc) it will be used, if a custom config file flag is presented it will be used, if flags are presented that will take precedence.

---

#### AWS
Command for verification
```shell
function-clarity verify aws <function name to verify> --function-region=<function region location> --flags (optional if you have configuration file)
```

below is the optional flags that the command uses.
| flag | Description |
| --- | --- |
| access key | AWS access key |
| secret key | AWS secret key |
| region | region to load the signature from (relevant only for code signing) |
| bucket | bucket to load signatures from (relevant only for code signing) |
| key | public key for verification |
