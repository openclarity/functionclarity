![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity (AKA FC) is an infrastructure solution for serverless functions signing and verification. The solution is combined from cli tool and a cloud specific infrastrucute for validation. The solution is suitable for ci/cd process where a code/image of serverless functions can be signed and uploaded beofre the function is created.

## how it works

![Untitled Diagram(1) drawio (1)](https://user-images.githubusercontent.com/109651023/189673319-5c66fb32-98f5-430c-a01f-4823ab51fc98.png)

* Deploy FC infrastructure (one time operation) which will result in function clarity eco system deployed in the users cloud account
* Using the FC cli, run code/image signing on user's environment - at this phase the code/image signature is uploaded to the cloud.
* deploy serverless function using the signed code/image content from the previous step
* Verifier lambda is trigerred upon create-function/update-function code events and performs the following:
  * fetch the verfied function code
  * analayze the code image/zip
  * check whether its signed by FC and act accordingly:
    * detect - marks the function with the verfication results
    * block - block the function from running in case its not verified
    * notify - send notification to queue.
---

**NOTE**:
at the moment only aws cloud provider is supported, additional cloud providers are on the roadmap
  
---

## Install Fuction Clarity
Fill installation instructions once the distribution is ready
## Quick start
The quick start will be conducted against aws account, we will show how to:
* Init and deploy FC
* Sign and upload code
* create aws function
* Check verfication
  * From the cloud account
  * From FC command line

### Init and deploy FC
The command prompts the user to enter information regarding the installation of FC.
When the command finishes to run FC will be deployed to aws account and a configuration file will be created locally under ~/.fc, the default values for the sign/verify commands will be taken from the config file unless flags are supplied.
```shell
./function-clarity init aws
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
The command below will sign folder with code and upload it to the user's cloud account

```shell
./function-clarity sign aws code /sample-code-verified-folder

using config file: /Users/shaiembon/.fc
Enter password for private key:
MEYCIQDskDWwLEURdALycGH/ntCRjA5G74yJ/qeSDzHTQSRY8gIhALE6Z5XW/iyjz++rzrdhzskPwfwW2gAMjK1H9lCXOGom
Code uploaded successfully
```
### Deploy function or update function code
Use aws cli to deploy lambda or update lambda code
### Verify function code
If you completed "init and deployment" step a verfier function runs in your cloud account and handles CreateFunction/UpdateFunctionCode events, after several minutes your lambda function will be tagged with FC message that the function is verified:

![image](https://user-images.githubusercontent.com/109651023/189880644-bed91413-a81c-4b03-b6f8-00ebea6606a0.png)

You can also use the cli to peform manual verification of a function:
```shell
./function-clarity verify aws funcclarity-test-signed --function-region=us-east-2
using config file: /Users/shaiembon/.fc
Verified OK
```

## Advanced usage
FC supports many features, we will elaborate on the commands and its usage.

### Init command detailed usage
#### aws
| Input | Description |
| --- | --- |
| access key | aws access key |
| secret key | aws secret key |
| region | region to deploy FC |
| default bucket | bucket to deploy code signatures and FC verifier lambda code for the deployment |
| post verification action | action to perform upon validation results (detect, block or leave empty for no action to perform) |
| sns arn | in case you would like to notify to an sns queue in case function is not verified |
| CloudTrail | cloud trail to use, can be empty and a new trail will be created |
| keyless mode (y/n) | select whether you would like to work in keylesss mode |
| public key for code signing | path to public key to use when verifing functions, can leave empty and a key-pair will be created |
| privte key for code signing | in case a public key path was entered, supply the corresponding private key path |


### Sign command detailed usage
#### aws
FC supports signing of code from local folder and images.
When signing images, make sure you are logged in to the docker repository where your images deployed.
For code signing use the command:
```shell
function-clarity sign aws code <folder to sign> --flags
```
For image singing use the command:
```shell
function-clarity sign aws image <image url> --flags
```
---

**NOTE**:
In case a default config file exists (under ~/.fc) it will be used, in case a custom config file is presented it will be used, if flags are presented that will take precedence.

---
below is the optional flags that the command uses.
| flag | Description |
| --- | --- |
| access key | aws access key |
| secret key | aws secret key |
| region | region to deploy signature |
| bucket | bucket to deploy code signature |
| privatekey | key to sign code with |




