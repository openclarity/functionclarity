# function-clarity
![image](https://user-images.githubusercontent.com/109651023/189649537-95638785-618f-4c74-93af-2cafedec2f07.png)
FunctionClarity (AKA FC) is an infrastructure solution for serverless functions (running code/image) signing and verification. The solution is combined from cli tool and a cloud specific infrastrucute for validation. The solution is suitable for ci/cd process where a code/image of serverless functions can be signed and uploaded beofre the function is created.

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

## Getting started
### Install Fuction Clarity
Fill installation instructions once the distribution is ready
### Quick start
We will show how to:
* Init and deploy FC
* Sign and upload code
* create aws function
* Check verfication
  * From the cloud account
  * From FC command line
