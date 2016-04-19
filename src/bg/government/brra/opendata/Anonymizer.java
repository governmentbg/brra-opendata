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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
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
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

public class Anonymizer {

    private static final String DOCUMENT_URL_ATTRIBUTE = "DocumentURL";
    private static final String IDENTIFIER_TYPE_ELEMENT = "IndentType";
    private static final String IDENTIFIER_ELEMENT = "Indent";
    private static final String PASSPORT_ELEMENT = "Passport";
    private static final String ADDRESS_ELEMENT = "Address";
    
    private static final String ID_CARD_PATTERN = "(л.к.|Л.К.|л.к|лична карта)( ){0,1}№( ){0,1}{0,1}\\d{9}";
    private static final String PERSONAL_ID_PATTERN = "(ЕГН|егн|ЛНЧ|лнч)( ){0,1}(:|-|;|,){0,1}( ){0,2}\\d{6,11}";
    
    // all of these elements may hold addresses that should be anonymized
    private static final List<String> ANONYMIZABLE_ADDRESS_PARENTS = Arrays.asList(new String[] {
        "BranchManager", "ActualOwner", "AtPawnCreditor", "DebtorOverSecureClaim", "Depositor", 
        "Depozitar", "Distraint", "LimitedLiabilityPartner", "ManagerOfTradeEnterprise", "PersonConcerned", "PledgeCreditor", 
        "PledgeExecutionDepozitar", "Pledgor", "Procurator", "CoOperative2", "SecuredClaimDebtor", "SpecialManager", 
        "SupervisionBodyMember", "SupervisionBodyMemberFull", "SupervisionBodyMemberFullSecIns", "SupervisionBodyMemberFullThirdIns", 
        "SupervisionBodyMemberFullSecIns", "Trustee", "TrusteeSecIns", "TrusteeThirdIns", "UnlimitedLiabilityPartner"}); 

    // full-text elements potentially containing personal data
    private static final List<String> IGNORED_ELEMENT_CONTENTS = Arrays.asList(new String[] {"Description033"});
    
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
        if (args.length != 2) {
            System.out.println("Program arguments: rootDir targetDir");
            System.exit(0);
        }
        String root = args[0];
        String targetDir = args[1];
        
        salts = deserializeSalts();

        try {
            for (int year = 2008; year <= 2016; year++) {
                for (int month = 1; month <= 12; month++) {
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
                }
            }            
        } finally {
            serializeSalts();
        }
    }

    static void processFile(InputStream in, Writer writer) throws XMLStreamException,
            UnsupportedEncodingException {
        XMLEventWriter eventWriter = factory.createXMLEventWriter(writer);
        XMLEventReader eventReader = inFactory.createXMLEventReader(in);
        XMLEventFactory eventFactory = XMLEventFactory.newFactory();
        
        boolean identifierStarted = false;
        boolean indentTypeStarted = false;
        boolean passportStarted = false;
        boolean anonymizableAddressParentStarted = false;
        boolean addressStarted = false;
        boolean ignoredElementStarted = false;
        String identifierType = "";
        String identifier = "";
        while (eventReader.hasNext()) {
            // The logic is as follows:
            // write all elements, except <Indent>. Store the <Indent> and <IndentType> in local variables, and 
            // at the end of the parent element, append the <Indent> - anonymized, if it was an EGN. 
            // (Identifiers are only present for Person and Subject elements.)
            XMLEvent event = eventReader.nextEvent();
            
            if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(IDENTIFIER_ELEMENT)) {
                identifierStarted = true;
            } else if (event.getEventType() == XMLEvent.END_ELEMENT && event.asEndElement().getName().getLocalPart().equals(IDENTIFIER_ELEMENT)) {
                identifierStarted = false;
                // if the identifier type is already parsed, we are ready to write the identifier
                if (!identifierType.isEmpty()) {
                    writeIdentifier(eventWriter, eventFactory, identifierType, identifier, event.asEndElement().getName());
                    identifier = "";
                    identifierType = "";
                }
            } else if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getAttributeByName(new QName(DOCUMENT_URL_ATTRIBUTE)) != null) {
                // we don't want to give the document URLs - they are unstructured (image) data which gets 
                // scraped and puts a lot of pressure on the servers
                StartElement original = event.asStartElement();
                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributes = original.getAttributes();
                List<Attribute> allowedAttributes = new ArrayList<>();
                while (attributes.hasNext()) {
                    Attribute attr = attributes.next();
                    if (!attr.getName().getLocalPart().equals(DOCUMENT_URL_ATTRIBUTE)) {
                        allowedAttributes.add(attr);
                    }
                }
                event = eventFactory.createStartElement(original.getName(), allowedAttributes.iterator(), original.getNamespaces());
                eventWriter.add(event);
            } else if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(PASSPORT_ELEMENT)) {
                passportStarted = true;
            } else if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(ADDRESS_ELEMENT)) {
                addressStarted = true;
                eventWriter.add(event); //write start address tag, but contents will not be written if they shouldn't
            } else if (event.getEventType() == XMLEvent.START_ELEMENT && ANONYMIZABLE_ADDRESS_PARENTS.contains(event.asStartElement().getName().getLocalPart())) {
                anonymizableAddressParentStarted = true;
            } else if (event.getEventType() == XMLEvent.START_ELEMENT && IGNORED_ELEMENT_CONTENTS.contains(event.asStartElement().getName().getLocalPart())) {
                ignoredElementStarted = true;
            } else if (!identifierStarted && !passportStarted && !(anonymizableAddressParentStarted && addressStarted) && !ignoredElementStarted){
                if (event.getEventType() == XMLEvent.CHARACTERS) {
                    // remove all references to identity card and personal identifiers from freetext before adding character event
                    // these references should be cleaned by the agency
                    String anonymizedContent = event.asCharacters().getData().replaceAll(ID_CARD_PATTERN, "");
                    anonymizedContent = anonymizedContent.replaceAll(PERSONAL_ID_PATTERN, "");
                    eventWriter.add(eventFactory.createCharacters(anonymizedContent));
                } else {
                    eventWriter.add(event);
                }
            }

            if (event.getEventType() == XMLEvent.START_ELEMENT && event.asStartElement().getName().getLocalPart().equals(IDENTIFIER_TYPE_ELEMENT)) {
                indentTypeStarted = true;
            }
            
            if (event.getEventType() == XMLEvent.END_ELEMENT && event.asEndElement().getName().getLocalPart().equals(IDENTIFIER_TYPE_ELEMENT)) {
                indentTypeStarted = false;
                // if the identifier is already parsed, we are ready to write it
                if (!identifier.isEmpty()) {
                    writeIdentifier(eventWriter, eventFactory, identifierType, identifier, event.asEndElement().getName());
                    identifier = "";
                    identifierType = "";
                }
            }
            
            if (event.getEventType() == XMLEvent.END_ELEMENT) {
                String endTagName = event.asEndElement().getName().getLocalPart();
                if (endTagName.equals(PASSPORT_ELEMENT)) {
                    passportStarted = false;
                }
                if (endTagName.equals(ADDRESS_ELEMENT)) {
                    addressStarted = false;
                }
                if (ANONYMIZABLE_ADDRESS_PARENTS.contains(endTagName)) {
                    anonymizableAddressParentStarted = false;
                }
                if (IGNORED_ELEMENT_CONTENTS.contains(endTagName)) {
                    ignoredElementStarted = false;
                }
                
                // upon ending of Person or Subject, reset everything
                if (endTagName.equals("Person") || endTagName.equals("Subject")
                        || endTagName.equals("NewOwner") || endTagName.equals("OldOwner") 
                        || endTagName.equals("BranchSubject") || endTagName.equals("Petitioner")) {
                    identifierStarted = false;
                    indentTypeStarted = false;
                    identifierType = "";
                    identifierType = "";
                }
            }
            
            // assuming all characters will be pushed as one event, as the strings are very short
            if (event.getEventType() == XMLEvent.CHARACTERS) {
                if (indentTypeStarted) {
                    identifierType = event.asCharacters().getData();
                } else if (identifierStarted) {
                    identifier = event.asCharacters().getData();
                }
            }
        }
    }

    private static void writeIdentifier(XMLEventWriter eventWriter, XMLEventFactory eventFactory,
            String identifierType, String identifier, QName xmlName) throws UnsupportedEncodingException,
            XMLStreamException {
        String prefix = xmlName.getPrefix();
        String uri = xmlName.getNamespaceURI();
        // always output the identifier, but hash it if it's EGN (or BirthDate or LNCH for foreigners). Undefined needed because sometimes there's EGN there
        if (!identifier.isEmpty() && identifierType.equals("EGN") || identifierType.equals("BirthDate") || identifierType.equals("LNCH") || identifierType.equals("Undefined")) {
            String salt = getSalt(identifier);
            identifier = DatatypeConverter.printHexBinary(digester.digest((salt + identifier).getBytes("UTF-8")));
        }
        eventWriter.add(eventFactory.createStartElement(prefix, uri, IDENTIFIER_ELEMENT));
        eventWriter.add(eventFactory.createCharacters(identifier));
        eventWriter.add(eventFactory.createEndElement(prefix, uri, IDENTIFIER_ELEMENT));
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
