package myconext.saml;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SamlProvider {
    static {
        OpenSamlInitializationService.initialize();
    }

    private static Base64 BASE64 = new Base64(0, new byte[]{'\n'});

    public AuthnRequest authnRequestFromXml(String xml, boolean deflated) throws UnmarshallingException, XMLParserException, IOException {
        byte[] decoded = BASE64.decode(xml);
        xml = deflated ? inflate(decoded) : new String(decoded, UTF_8);
        Document document = XMLObjectProviderRegistrySupport.getParserPool().parse(new ByteArrayInputStream(xml.getBytes()));
        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        XMLObject xmlObject = unmarshallerFactory.getUnmarshaller(element).unmarshall(element);
//        TODO Signature signature = validateSignature((SignableSAMLObject) parsed, verificationKeys);
        return (AuthnRequest) xmlObject;
    }


    static String samlEncode(byte[] b) {
        return BASE64.encodeAsString(b);
    }

    static byte[] samlDecode(String s) {
        return BASE64.decode(s);
    }

    static byte[] samlDeflate(String s) {
        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            DeflaterOutputStream deflater = new DeflaterOutputStream(b, new Deflater(Deflater.DEFLATED, true));
            deflater.write(s.getBytes(StandardCharsets.UTF_8));
            deflater.finish();
            return b.toByteArray();
        } catch (IOException ex) {
            throw new Saml2Exception("Unable to deflate string", ex);
        }
    }

    String inflate(byte[] b) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
        iout.write(b);
        iout.finish();
        return new String(out.toByteArray(), UTF_8);
    }

    static String samlInflate(byte[] b) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
            iout.write(b);
            iout.finish();
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new Saml2Exception("Unable to inflate string", ex);
        }
    }

}


