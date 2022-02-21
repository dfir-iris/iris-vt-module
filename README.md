# IrisVTModule

An interface module for VT and Iris to automatically enrich IOCs with VT insight.  
**Module type** : ``Processor``  
**Min IRIS version required** : ``> 1.3.0`` 

The module is preinstalled and registered by default on IRIS. For a manual installation please see the Installation section of this readme.

## Configuration 
The following configuration is available in the configuration section of the module on IRIS. 

- **VT API Key** : API key used by the module to connect to VT 
- **VT Key is premium** : Set to True to indicate the provided API Key is premium.
- **Manual triggers on IOCs** : Provides a right-click menu option on IOCs to trigger the VT module on selected elements. 
- **Triggers automatically on IOC create**: If set to true, the module runs each time an IOC is created. Disabled by default. 
- **Triggers automatically on IOC update**: If set to true, the module runs each time an IOC is updated. Disabled by default. 
- **Assign ASN tag to IP** : If set to true, creates a new tag with ASN info on the target IP IOC. 
- **IOC tag malicious threshold** : Float detection ratio above which the module adds a ``vt:malicious``. To disable, add a value > 100. 
- **IOC tag suspicious threshold**: Float detection ratio above which the module adds a ``vt:suspicious``. To disable, add a value > 100. 
- **Add VT report as new IOC attribute**: Creates a new attribute on the IOC, base on the VT report. Templates define on this configuration are used. 
- **Domain report template**: Jinja2 report template for domain IOCs. Refers to the raw report to assess which fields are available. 
- **IP report template**: Jinja2 report template for IP IOCs. Refers to the raw report to assess which fields are available. 
- **Hash report template**: Jinja2 report template for hash IOCs. Refers to the raw report to assess which fields are available. 

## Installation 
 The installation can however be done manually if required, 
either from sources or existing packages (go to step 3.)

1. Git clone this repository ``git clone https://github.com/dfir-iris/iris-vt-module.git && cd iris-vt-module``
2. Build the wheel : ``python3 setup.py bdist_wheel`` 
3. Copy the wheel into the IRIS app docker container ``docker cp iris_vt_module-XX-py3-none-any.whl container:/iriswebapp/dependencies/``
4. Get an interactive shell on the docker : ``docker exec -it container /bin/sh``
5. Install the new package ``pip3 install dependencies/iris_vt_module-XX-py3-none-any.whl``
