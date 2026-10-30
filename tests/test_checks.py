import unittest
from unittest.mock import patch
from grevora_recon.checks import public_dns_only

class DNSGuardTests(unittest.TestCase):
    @patch("grevora_recon.checks.socket.getaddrinfo")
    def test_blocks_private_resolution(self,m):
        m.return_value=[(None,None,None,None,("192.168.1.10",0))]
        with self.assertRaises(OSError): public_dns_only("example.test")
    @patch("grevora_recon.checks.socket.getaddrinfo")
    def test_allows_public_resolution(self,m):
        m.return_value=[(None,None,None,None,("93.184.216.34",0))]
        public_dns_only("example.test")

if __name__=="__main__": unittest.main()
