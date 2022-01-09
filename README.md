# SecureFaceVerification
A secure Face Verification tool using TFHE with API HNP. The implementation starts given face embedding vectors (from Facenet) in enrollment and athentication step. The aim is to combine this implementation focusing on secure server side with the one from liziyu0104 focusing on the client side experience to build a secure common tool for our common Lab "Learning on encrypted data" in the respective repository..

# Installation:
```python
2|  conda create -n SFV python=3.8  # create python3.8 environnement
3|  conda activate SFV
```
```python
pip install hnumpy-0.3.0-py3-none-any.whl
pip install py_zamavm-0.2.0-cp38-cp38-linux_x86_64.whl
pip install pycryptodome
```

# Usage
Use
```python
python3 rsa.py
```
for a buildin test of the RSA implementation for purposes of this project. Use
```python
python3 simulation.py
```
for a buildin test of the implemented client and server structures.
