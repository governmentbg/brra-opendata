package bg.government.brra.opendata;

import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

import javax.xml.stream.XMLStreamException;

public class AnonymizerTest {

    /**
     * Using a main method instead of junit in order to limit the dependencies. The tests are rather simple and no toolkit is needed
     */
    public static void main(String[] args) {
        parserTest();
        saltTest();
        System.out.println("Tests were successful");
    }

    private static void saltTest() {
        String salt = Anonymizer.generateSalt();
        if (salt.length() < 30) {
            throw new IllegalStateException("Salt should be bigger than 30");
        }
    }

    private static void parserTest() {
        InputStream in = AnonymizerTest.class.getResourceAsStream("test.xml");
        StringWriter writer = new StringWriter();
        try {
            Anonymizer.processFile(in, writer);
            String result = writer.toString();
            // test that the Identifiers are anonymized
            String[] identifiers = new String[] { "1111111111", "2222222222", "3333333333", "4444444444",
                    "5555555555", "7777777777", "9999999999", "551155115511", "1122334455" };
            for (String id : identifiers) {
                if (result.contains(id)) {
                    throw new IllegalStateException("Identifier is not anonymized");
                }
            }
            
            if (result.contains("</Person><Indent>")) {
                throw new IllegalStateException("<Indent> tag is at the wrong place");
            }
            
            // test that the document URLs are removed
            if (result.contains("https://public.brra.bg/Documents/12345") || result.contains("DocumentURL")) {
                throw new IllegalStateException("Document URLs are not removed");
            }
            
            if (result.contains("<Area>р-н Младост</Area>") || result.contains("<Block>123</Block>")) {
                throw new IllegalStateException("Personal address not anonymized");
            }
            
            if (result.contains("Passport") || result.contains("<Number>1234567</Number>")) {
                throw new IllegalStateException("Passport details not anonymized");
            }
            
            if (result.contains("ЕГН 1234567890") || result.contains("ЛНЧ")) {
                throw new IllegalStateException("EGN or LNCH not anonymized");
            }
            
            // test that some common content were preserved
            String[] keywords = new String[] {"Годишен финансов отчет", "Сканирано копие на заявление образец Г2", "TransferringEnterprise", "IncomingPackageInfo", "ТЕСТТЕСТ"};
            for (String keyword : keywords) {
                if (!result.contains(keyword)) {
                    throw new IllegalStateException("Missing expected content " + keyword);
                }
            }
        } catch (UnsupportedEncodingException | XMLStreamException e) {
            throw new IllegalStateException("Problem parsing", e);
        }
        
    }
}
