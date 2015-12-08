package bg.government.brra.opendata;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

public class Anonymizer {

    private static final String IDENTIFIER_TYPE_ELEMENT = "IndentType";
    private static final String IDENTIFIER_ELEMENT = "Indent";
    // per-person salts. Stored in serialized form and reused between runs of the program, so that each person
    // has a the same anonymized identifier
    private static Map<String, String> salts = new HashMap<>();

    static XMLOutputFactory factory = XMLOutputFactory.newInstance();
    static XMLEventFactory eventFactory = XMLEventFactory.newInstance();
    static XMLInputFactory inFactory = XMLInputFactory.newInstance();
    static MessageDigest digester = createMessageDigest();

    private static MessageDigest createMessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
    
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Program arguments: rootDir targetDir year month");
            System.exit(0);
        }
        String root = args[0];
        String targetDir = args[1];
        String year = args[2];
        String month = args[3];
        
        salts = deserializeSalts();
        
        File dir = new File(root + "/" + year + "/" + month);
        
                
        File target = new File(targetDir, year + "/" + month + "/");
        target.mkdirs();
        
        // iterating all files in the directory, and parsing them. Outputting their content exactly as it is to the result file,
        // except for personal identifiers, which are anonymized using a salted hash.
        for (File file : dir.listFiles()) {
            try (InputStream in = new FileInputStream(file)) {
                try (Writer writer = new OutputStreamWriter(new FileOutputStream(new File(targetDir, year + "/" + month + "/" + file.getName())), "UTF-8")) {
                    processFile(in, writer);
                } catch (Exception ex) {
                    // abort the whole process
                    throw new RuntimeException(ex);
                }
            } catch (Exception ex) {
                // abort the whole process
                throw new RuntimeException(ex);
            }
        }
        
        serializeSalts();
    }

    static void processFile(InputStream in, Writer writer) throws XMLStreamException,
            UnsupportedEncodingException {
        XMLEventWriter eventWriter = factory.createXMLEventWriter(writer);
        XMLEventReader eventReader = inFactory.createXMLEventReader(in);
        
        boolean identifierStarted = false;
        boolean indentTypeStarted = false;
        String identifierType = "";
        String identifier = "";
        while (eventReader.hasNext()) {
            // The logic is as follows:
            // write all elements, except <Indent>. Store the <Indent< and <IndentType> in local variables, and 
            // at the end of the parent element, append the <Indent> - anonymized, if it was an EGN. 
            // (Identifiers are only present for Person and Subject elements.)
            XMLEvent event = eventReader.nextEvent();
            
            if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(IDENTIFIER_ELEMENT)) {
                identifierStarted = true;
            } else if (event.getEventType() == XMLEvent.END_ELEMENT && event.asEndElement().getName().getLocalPart().equals(IDENTIFIER_ELEMENT)) {
                identifierStarted = false;
            } else if (!identifierStarted){
                eventWriter.add(event);
            }
            
            if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(IDENTIFIER_TYPE_ELEMENT)) {
                indentTypeStarted = true;
            }
            
            if (event.getEventType() == XMLEvent.END_ELEMENT && event.asEndElement().getName().getLocalPart().equals(IDENTIFIER_TYPE_ELEMENT)) {
                indentTypeStarted = false;
            }
            
            // assuming all characters will be pushed as one event, as the strings are very short
            if (event.getEventType() == XMLEvent.CHARACTERS) {
                if (indentTypeStarted) {
                    identifierType = event.asCharacters().getData();
                } else if (identifierStarted) {
                    identifier = event.asCharacters().getData();
                }
            }
        
            if (event.getEventType() == XMLEvent.END_ELEMENT) {
                QName xmlName = event.asEndElement().getName();
                String name = xmlName.getLocalPart();
                if (name.equals("Person") || name.equals("Subject")) {
                    String prefix = xmlName.getPrefix();
                    String uri = xmlName.getNamespaceURI();
                    // always output the identifier, but hash it if it's EGN
                    if (identifierType.equals("EGN")) {
                        String salt = getSalt(identifier);
                        identifier = DatatypeConverter.printHexBinary(digester.digest((salt + identifier).getBytes("UTF-8")));
                    }
                    eventWriter.add(eventFactory.createStartElement(prefix, uri, IDENTIFIER_ELEMENT));
                    eventWriter.add(eventFactory.createCharacters(identifier));
                    eventWriter.add(eventFactory.createEndElement(prefix, uri, IDENTIFIER_ELEMENT));
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> deserializeSalts() throws Exception {
        File file = new File("salts");
        if (!file.exists()) {
            return new HashMap<>();
        }
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(file))) {
            return (HashMap<String, String>) in.readObject();
        }
    }
    
    private static void serializeSalts() throws Exception {
        File file = new File("salts");
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(file))) {
            out.writeObject(salts);
        }
    }

    private static String getSalt(String egn) {
        String result = salts.get(egn);
        if (result == null) {
            result = generateSalt();
            salts.put(egn, result);
        }
        return result;
    }

    static String generateSalt() {
        Random random = new Random();
        int max = 30 + random.nextInt(10);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < max; i ++) {
            builder.append((char) 32 + random.nextInt(94));
        }
        return builder.toString();
    }
}
