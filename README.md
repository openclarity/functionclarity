![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity is a code integrity solution for serverless functions. It allows users to sign their serverless functions and verify their integrity prior to their execution in their cloud environments. FunctionClarity includes a CLI tool, complemented by a "verification" function deployed in the target cloud account.  The solution is designed for CI/CD insertion, where the serverless function code/images can be signed and uploaded before the function is created in the cloud repository.

This version supports serverless functions on AWS (Lambda functions) only, support for Azure functions and Google functions/cloud-run are part of the near-term roadmap plan.

## How does it work?

![FunctionClarity Diagram](https://user-images.githubusercontent.com/110329574/197707276-10cd650e-a84d-4a9f-a83a-ee60dc2cbf28.png)

* Deploy FunctionClarity – deploy FunctionClarity "validation" function in the target cloud account (a one time operation); this function will scan and verify new functions when created or updated in the target account
* Sign functions  - use FunctionClarity CLI to sign the function code or image in the user’s environment, and then upload it to the target cloud account
* Deploy the serverless function - using the signed function code/image 
* Verify functions -  the FunctionClarity verifier function is triggered when user functions are created or updated, and does the following:
  * Fetches the function code from the cloud account to the local machine
  * Verifies the signature of the function code image or zip file
  * Follows one of these actions, based on the verification results:
    * Detect - marks the function with the verification results
    * Block - tags the function as 'blocked', if the signature is not correctly verified, otherwise does nothing
    * Notify - sends a notification of the verification results to an SNS queue

If a function is tagged as blocked, it will be prevented from being run by AWS when it is invoked.

## Download FunctionClarity
Go to the [function clarity latest release](https://github.com/openclarity/functionclarity/releases/latest):
* Create a folder, download
* Download ```aws_function.tar.gz``` for your OS, and extract it to the folder

## Quick start
This section explains how to get started using FunctionClarity. These steps are involved:

* Initialize and deploy FunctionClarity
* Sign and upload srverless function code
* Sign and verify new AWS functions
* Verify functions:
  * From the cloud account
  * From the FunctionClarity command line

### Initialize and deploy FunctionClarity
Follow these  steps from a command line, to install FunctionClarity in your AWS account.
Run the command from the folder in which the FunctionClarity tar file is located.
As part of the deployment, a verifier function will be deployed in your cloud account, which will be triggered when lambda functions are created or updated in the account. This function  verifies function identities and signatures, according to the FunctionClarity settings.
A configuration file will also be created locally, in ```~/.fc```, with default values that are used  when signing or verifying functions, unless specific settings are set with command line flags.

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

### Sign function code
Use the command below to  sign a folder containing function code, and then upload it to the user cloud account.

```shell
./function-clarity sign AWS code /sample-code-verified-folder

using config file: /Users/john/.fc
Enter password for private key:
MEYCIQDskDWwLEURdALycGH/ntCRjA5G74yJ/qeSDzHTQSRY8gIhALE6Z5XW/iyjz++rzrdhzskPwfwW2gAMjK1H9lCXOGom
Code uploaded successfully
```
### Deploy a function or update function code
Use AWS cli to deploy a signed lambda function to your cloud account, or to  update lambda code in the account

### Verify function code

#### Verify automatically on function create or update events

If the verifier function is deployed in your account, any function create or update event will trigger it to verify the new or updated function. It will follow the post-verification action (detect, block, or notify). 

If the action is 'detect', the function will be tagged with the FunctionClarity message that the function is verified:

![image](https://user-images.githubusercontent.com/109651023/189880644-bed91413-a81c-4b03-b6f8-00ebea6606a0.png)

#### Verify manually
You can also use the CLI to manually verify a function. In this case, the function is downloaded from the cloud account, and then verified locally.

```shell
./function-clarity verify aws funcclarity-test-signed --function-region=us-east-2
using config file: /Users/john/.fc
Verified OK
```

## Advanced use
FunctionClarity includes several advanced commands and features, which are described below.

FunctionClarity leverages [cosign](https://github.com/sigstore/cosign) to sign and verify, code, for both  key-pair and keyless signing techniques.

### Init command detailed use
```shell
function-clarity init aws
```
| Argument                       | Description                                                                                        |
|-----------------------------|----------------------------------------------------------------------------------------------------|
| access key                  | AWS access key                                                                                     |
| secret key                  | AWS secret key                                                                                     |
| region                      | AWS region in which to deploy FunctionClarity                                                                   |
| default bucket              | AWS bucket in which to deploy code signatures and FunctionClarity verifier lambda code for the deployment       |
| post verification action    | action to perform after verification (detect, block, or notify;  leave empty for no action to be performed)  |
| sns arn                     | for the 'notify' action,  an SNS queue for notifications if verification fails                  |
| CloudTrail                  | AWS cloudtrail to use; if  empty a new trail will be created                                   |
| keyless mode (y/n)          | work in keyless mode                                              |
| public key for code signing | path to public key to use when verifying functions; if blank a new key-pair will be created |
| privte key for code signing | private key path; used only if a public key path is also supplied                   |

| Flag               | Description                                                             |
|--------------------|-------------------------------------------------------------------------|
| only-create-config | determine whether to only create config file without actually deploying |

### Deploy command detailed use
The ```deploy``` command does the same as ```init```, but it uses the config file, so you don't
need to supply parameters  using the command line
```shell
function-clarity deploy aws
```

### Sign command detailed use
FunctionClarity supports signing  code from local folders and images.
When signing images, you must be logged in to the docker repository where your images deployed.


---

**NOTE**:
If  a default config file exists (in  ```~/.fc```) it will be used. If a custom config file flag is included in the command line, it will be used instead of the default file. If flags are included in the command line, they will be used and take precedence.

---
### Examples
To sign code, use this command:
```shell
function-clarity sign aws code <file/folder to sign> --flags (optional if you have configuration file)
```
To sign images,  use this command:
```shell
function-clarity sign aws image <image url> --flags (optional if you have configuration file)
```
These are  optional flags for the ```sign```  command:

| flag       | Description                                                      |
|------------|------------------------------------------------------------------|
| access key | AWS access key                                                   |
| secret key | AWS secret key                                                   |
| region     | AWS region in which to deploy signature (relevant only for code signing)      |
| bucket     | AWS bucket in which to deploy code signature (relevant only for code signing) |
| privatekey | key to use to sign code                                            |


### Verify command detailed use

---

**NOTE**:
If  a default config file exists (in  ```~/.fc```) it will be used. If a custom config file flag is included in the command line, it will be used instead of the default file. If flags are included in the command line, they will be used and take precedence.

---

Command for verification
```shell
function-clarity verify aws <function name to verify> --function-region=<function region location> --flags (optional if you have configuration file)
```

These are  optional flags for the ```verify``` command:

| flag       | Description                                                        |
|------------|--------------------------------------------------------------------|
| access key | AWS access key                                                     |
| secret key | AWS secret key                                                     |
| region     | AWS region from which  to load the signature from (relevant only for code signing) |
| bucket     | AWS bucket from which to load signatures from (relevant only for code signing)    |
| key        | public key for verification                                        |
