package com.pagatodo360.test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.X509Certificate;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;

import com.pagatodo360.firmador.Firmador;

public class FirmadorTest {
	
	public FirmadorTest() {
    
	}

	@Test
	public void firmarXML() throws URISyntaxException, ParserConfigurationException, XMLSecurityException, org.xml.sax.SAXException
	{
		 Base64.Decoder dec = Base64.getDecoder();
		//String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><facturaElectronicaEstandar> AQUI VA LA FACTURA XML </facturaElectronicaEstandar>";
		
		String facturaB64 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pg0KPGZhY3R1cmFFbGVjdHJvbmljYUNvbXByYVZlbnRhIHhzaTpub05hbWVzcGFjZVNjaGVtYUxvY2F0aW9uPSJmYWN0dXJhRWxlY3Ryb25pY2FDb21wcmFWZW50YS54c2QiIHhtbG5zOm5zMj0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSI+DQogICAgPGNhYmVjZXJhPg0KICAgICAgICA8bml0RW1pc29yPjEwMTU1MzcwMjc8L25pdEVtaXNvcj4NCiAgICAgICAgPHJhem9uU29jaWFsRW1pc29yPkRBVEVDIExUREE8L3Jhem9uU29jaWFsRW1pc29yPg0KICAgICAgICA8bXVuaWNpcGlvPlNhbnRhIENydXo8L211bmljaXBpbz4NCiAgICAgICAgPHRlbGVmb25vPjM1NTU4ODg1PC90ZWxlZm9ubz4NCiAgICAgICAgPG51bWVyb0ZhY3R1cmE+MTwvbnVtZXJvRmFjdHVyYT4NCiAgICAgICAgPGN1Zj40NTdDNjE4NjdGQkMxN0RCN0U3MUM3OTEyRjNFQTUzQzFEQzI5RTA2QTA0QTQ4OTQ1QUY2QkRDNzQ8L2N1Zj4NCiAgICAgICAgPGN1ZmQ+QlFjS2hRMncwUWtKQk5qVUV6TmtNMVJVUTNOa1k9UWo0eWRXOU1TMHBXVlVGZ3dOVVZHT0RFd01EY3dOPC9jdWZkPg0KICAgICAgICA8Y29kaWdvU3VjdXJzYWw+MDwvY29kaWdvU3VjdXJzYWw+DQogICAgICAgIDxkaXJlY2Npb24+Q0FMTEUgVkVMQVNDTyBOUk8uMjEzIFpPTkEgQ0VOVFJBTDwvZGlyZWNjaW9uPg0KICAgICAgICA8Y29kaWdvUHVudG9WZW50YSB4c2k6bmlsPSJ0cnVlIi8+DQogICAgICAgIDxmZWNoYUVtaXNpb24+MjAyMS0wOS0wOVQxMjowMjozNy4xMDM8L2ZlY2hhRW1pc2lvbj4NCiAgICAgICAgPG5vbWJyZVJhem9uU29jaWFsPkF5dGlhPC9ub21icmVSYXpvblNvY2lhbD4NCiAgICAgICAgPGNvZGlnb1RpcG9Eb2N1bWVudG9JZGVudGlkYWQ+MTwvY29kaWdvVGlwb0RvY3VtZW50b0lkZW50aWRhZD4NCiAgICAgICAgPG51bWVyb0RvY3VtZW50bz4zOTY0NzcyPC9udW1lcm9Eb2N1bWVudG8+DQogICAgICAgIDxjb21wbGVtZW50byB4c2k6bmlsPSJ0cnVlIi8+DQogICAgICAgIDxjb2RpZ29DbGllbnRlPkFBQUEzMzMzPC9jb2RpZ29DbGllbnRlPg0KICAgICAgICA8Y29kaWdvTWV0b2RvUGFnbz4xPC9jb2RpZ29NZXRvZG9QYWdvPg0KICAgICAgICA8bnVtZXJvVGFyamV0YSB4c2k6bmlsPSJ0cnVlIi8+DQogICAgICAgIDxtb250b1RvdGFsPjEwMDA8L21vbnRvVG90YWw+DQogICAgICAgIDxtb250b1RvdGFsU3VqZXRvSXZhPjEwMDA8L21vbnRvVG90YWxTdWpldG9JdmE+DQogICAgICAgIDxjb2RpZ29Nb25lZGE+MTwvY29kaWdvTW9uZWRhPg0KICAgICAgICA8dGlwb0NhbWJpbz4xPC90aXBvQ2FtYmlvPg0KICAgICAgICA8bW9udG9Ub3RhbE1vbmVkYT4xMDAwPC9tb250b1RvdGFsTW9uZWRhPg0KICAgICAgICA8bGV5ZW5kYT5sZXllbmRhPC9sZXllbmRhPg0KICAgICAgICA8dXN1YXJpbz51c3VhcmlvPC91c3VhcmlvPg0KICAgICAgICA8Y29kaWdvRG9jdW1lbnRvU2VjdG9yPjE8L2NvZGlnb0RvY3VtZW50b1NlY3Rvcj4NCiAgICA8L2NhYmVjZXJhPg0KICAgIDxkZXRhbGxlPg0KICAgICAgICA8YWN0aXZpZGFkRWNvbm9taWNhPjQ2NDMwMDwvYWN0aXZpZGFkRWNvbm9taWNhPg0KICAgICAgICA8Y29kaWdvUHJvZHVjdG9TaW4+NjEyOTE8L2NvZGlnb1Byb2R1Y3RvU2luPg0KICAgICAgICA8Y29kaWdvUHJvZHVjdG8+NDQ1NTU8L2NvZGlnb1Byb2R1Y3RvPg0KICAgICAgICA8ZGVzY3JpcGNpb24+bm9tYnJlIFByb2R1Y3RvPC9kZXNjcmlwY2lvbj4NCiAgICAgICAgPGNhbnRpZGFkPjE8L2NhbnRpZGFkPg0KICAgICAgICA8dW5pZGFkTWVkaWRhPjYyPC91bmlkYWRNZWRpZGE+DQogICAgICAgIDxwcmVjaW9Vbml0YXJpbz4xMDAwPC9wcmVjaW9Vbml0YXJpbz4NCiAgICAgICAgPG1vbnRvRGVzY3VlbnRvIHhzaTpuaWw9InRydWUiLz4NCiAgICAgICAgPHN1YlRvdGFsPjEwMDA8L3N1YlRvdGFsPg0KICAgICAgICA8bnVtZXJvU2VyaWUgeHNpOm5pbD0idHJ1ZSIvPg0KICAgICAgICA8bnVtZXJvSW1laSB4c2k6bmlsPSJ0cnVlIi8+DQogICAgPC9kZXRhbGxlPg0KPC9mYWN0dXJhRWxlY3Ryb25pY2FDb21wcmFWZW50YT4";
		String xml = new String(dec.decode(facturaB64));
		System.out.println("XML decodificado:\n " + xml);
		byte[] datos = xml.getBytes(StandardCharsets.UTF_8);
		
	    //String report_folder = new File("").getAbsolutePath();
	    //System.out.println("report folder : " + report_folder);
	        try { 
	        	//String path1 = new File(Firmador.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
	        	// System.out.println("path1 : " + path1);
	        	String path = "C:\\Certificado";//new File(FirmadorTest.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath(); 
	            System.out.println("path : " + path);          
	            
	            PrivateKey privateKey = Firmador.getPrivateKey(path + "\\DatecLtda_Priv.pem");
	            X509Certificate cert = Firmador.getX509Certificate(path + "\\DatecLtda_Cert.pem");
	      	            
	            byte[] xmlFirmado = Firmador.firmarDsig(datos, privateKey, cert);

	            String respuesta = new String(xmlFirmado);
	            System.out.println("\nFactura Firmada :\n"+respuesta);

	        } catch (IOException | GeneralSecurityException ex) {

	        	Logger.getLogger(FirmadorTest.class.getName()).log(Level.SEVERE, null, ex);
	        }
	}
}
