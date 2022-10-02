![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity (FC) is an infrastructure to sign and verify serverless functions in AWS cloud environments. This solution includes a CLI tool and a verifier function which is deployed in the cloud account.  The solution is suitable for a CI/CD process in which serverless function code/images can be signed and uploaded before the function is created in the cloud repository.

This version supports AWS only.

## How it works

![Untitled Diagram(1) drawio (1)](https://user-images.githubusercontent.com/109651023/189673319-5c66fb32-98f5-430c-a01f-4823ab51fc98.png)

* Deploy FunctionClarity – deploy FunctionClarity functions to the user cloud account (a one time operation); these functions scan and verify user functions when created or updated
* Sign functions  - use the FunctionClarity CLI to sign the function code or image in the user’s environment, and then upload it to the user cloud account
* Deploy the serverless function - using the signed function code/image 
* Veify functions -  the FunctionClarity function is triggered when user functions are created or updated, and does the following
  * Fetch the verified function code
  * Analyse the code image/zip
  * Check whether it is signed by FunctionClarity and act accordingly:
    * Detect - marks the function with the verification results
    * Block - block the function from running in case its not verified
    * Notify - send notification to queue


## Install FunctionClarity
Go to [function clarity latest release](https://github.com/openclarity/functionclarity/releases/latest):
* Create a folder, download and extract functionclarity file that matches your os.
* Download aws_function.tar.gz and extract it inside the folder from the previous step

## Quick start
This section explains how to get started using FunctionClarity. It is based on AWS.These steps are involved:

* Initialize and deploy FunctionClarity
* Sign and upload srverless function code
* Sign and verify new AWS functions
* Verify functions:
  * From the cloud account
  * From FunctionClarity command line

### Initialize and deploy FunctionClarity
Follow these following steps from a command line, to install FunctionClarity in your AWS account.
Run the command from the folder in which the FunctionClarity tar file is located.
As part of the deployment, a verifier function will be deployed in your cloud account, which will be triggered when lambda functions are created or updated. It will verify function identities and signatures, according to the FunctionClarity settings.
A configuration file will also be created locally, in ```~/.fc```, with default values that used to when signing or verifying functions, unless specific settings are set with command line flags.

1.	Run the command ```./function-clarity init AWS```
2.	When prompted, enter the following details:
```
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
```
3.	The installation process will continue, until complete:
```
    Private key written to cosign.key
    Public key written to cosign.pub
    deployment finished successfully
```


### Sign code
Use the command below to  sign a folder containing code, and then upload it to the user cloud account.

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
```shell
function-clarity init aws
```
| Input                       | Description                                                                                        |
|-----------------------------|----------------------------------------------------------------------------------------------------|
| access key                  | AWS access key                                                                                     |
| secret key                  | AWS secret key                                                                                     |
| region                      | region to deploy FunctionClarity                                                                   |
| default bucket              | bucket to deploy code signatures and FunctionClarity verifier lambda code for the deployment       |
| post verification action    | action to perform upon validation results (detect, block or leave empty for no action to perform)  |
| sns arn                     | in case you would like to notify to an sns queue in case function is not verified                  |
| CloudTrail                  | cloud trail to use, can be empty and a new trail will be created                                   |
| keyless mode (y/n)          | select whether you would like to work in keyless mode                                              |
| public key for code signing | path to public key to use when verifying functions, can leave empty and a key-pair will be created |
| privte key for code signing | in case a public key path was entered, supply the corresponding private key path                   |

| Flag               | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| only-create-config | determine whether to only create config file without actually deploying |

### Deploy command detailed usage
deploy command will do the same as init command does, but it uses the config file, so the user doesn't
need to supply parameters interactively using the command line
```shell
function-clarity deploy aws
```

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
function-clarity sign aws code <file/folder to sign> --flags (optional if you have configuration file)
```
For image singing use the command:
```shell
function-clarity sign aws image <image url> --flags (optional if you have configuration file)
```
below is the optional flags that the command uses:

| flag       | Description                                                      |
|------------|------------------------------------------------------------------|
| access key | AWS access key                                                   |
| secret key | AWS secret key                                                   |
| region     | region to deploy signature (relevant only for code signing)      |
| bucket     | bucket to deploy code signature (relevant only for code signing) |
| privatekey | key to sign code with                                            |


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

below is the optional flags that the command uses:

| flag       | Description                                                        |
|------------|--------------------------------------------------------------------|
| access key | AWS access key                                                     |
| secret key | AWS secret key                                                     |
| region     | region to load the signature from (relevant only for code signing) |
| bucket     | bucket to load signatures from (relevant only for code signing)    |
| key        | public key for verification                                        |
