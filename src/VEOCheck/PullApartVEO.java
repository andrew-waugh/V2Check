/*
 * Copyright Public Record Office Victoria 2005, 2015
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */
package VEOCheck;

/**
 * *************************************************************
 *
 * P U L L A P A R T V E O
 *
 * This class pulls apart a VEO. It does two functions. First, it copies the XML
 * document, without the DocumentData, into a temporary file. Second, it
 * (optionally) extracts the DocumentData into individual files that can be
 * examined, tested for correctness, and virus checked.
 *
 * Extracting the XML document into a temporary file is because of a design
 * limitation with DOM. When DOM opens a document it reads the entire document
 * into an in-memory model. This makes it horribly resource intensive (and slow)
 * for VEOs that contain any realistic DocumentData. It is much faster to
 * process the VEO using SAX to produce a smaller temporary file, and then read
 * the temporary file using DOM.
 *
 * <ul>
 * <li>20110614 Changed OutputStreamWriter from 8859_1 to UTF-8
 * <li>20150518 Imported into NetBeans IDE and cleaned up. Added eicar.txt
 * generation
 * <li>20180601 Now uses VERSCommon instead of VEOSupport
 * </ul>
 *
 * Andrew Waugh (andrew.waugh@prov.vic.gov.au) Copyright 2005, 2015 PROV
 *
 *************************************************************
 */
import VERSCommon.*;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Stack;
import java.util.ArrayList;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.ext.DefaultHandler2;

public class PullApartVEO extends DefaultHandler2 {

    SAXParserFactory spf;
    SAXParser sax;          // parser to read the VEO
    Stack<String> currentElement; // stack of elements recognised
    Stack<String> currentId; // stack of ids
    String veoName;         // filename of VEO
    BufferedWriter bw;	    // where to write the edited VEO
    ArrayList<String> files; // list of files containing the extracted document content
    StringBuffer renderingKeywords; // the capture contents of vers:RenderingKeywords element as they are read
    boolean emptyElement;   // true if no content between start and end element events
    boolean extractContent; // true if content of document data is to be extracted
    boolean virusScanning;  // true if the document data is to be virus scanned
    boolean base64;	    // true if last vers:RenderingKeywords element contained the characters 'b64' or 'B64'
    int docNo;		    // document number
    int encNo;		    // encoding number
    String fileExt;         // contains the file extension of the last vers:sourceFileIdentifier
    boolean outputOpen;     // true when we have a file open for content
    boolean outputFilename; // true if outputting a vers:DocumentData
    FileOutputStream contentfos; // file descriptors for content...
    BufferedOutputStream contentbos;
    OutputStreamWriter contentosw;
    B64 b64;		    // base64 decoder
    Path tempDir;           // temporary directory in which to put the extracted content

    /**
     * Default constructor
     *
     * @param veoName the name of the veo being pulled apart
     */
    public PullApartVEO(String veoName) {
        int i;

        // set up SAX parser
        try {
            spf = SAXParserFactory.newInstance();
            spf.setValidating(false);
            // spf.setFeature("http://xml.org/sax/features/resolve-dtd-uris", false);
            sax = spf.newSAXParser();

            XMLReader xmlReader = sax.getXMLReader();
            xmlReader.setProperty("http://xml.org/sax/properties/lexical-handler", this);
        } catch (SAXNotRecognizedException e) {
            System.err.println("SAXNotRecognizedException:" + e.getMessage());
            System.exit(-1);
        } catch (SAXNotSupportedException e) {
            System.err.println("SAXNotSupportedException:" + e.getMessage());
            System.exit(-1);
        } catch (ParserConfigurationException e) {
            System.err.println("SAX Parser Exception:" + e.getMessage());
            System.exit(-1);
        } catch (SAXException e) {
            System.err.println("SAXException:" + e.getMessage());
            System.exit(-1);
        }

        // remember the veo name
        if ((i = veoName.lastIndexOf('.')) != -1) {
            if (i == 0) {
                this.veoName = "noName";
            } else {
                this.veoName = veoName.substring(0, i);
            }
        } else {
            this.veoName = veoName;
        }

        currentElement = new Stack<String>();
        currentId = new Stack<String>();
        bw = null;
        files = new ArrayList<String>();
        renderingKeywords = new StringBuffer();
        emptyElement = false;
        extractContent = false;
        virusScanning = false;
        base64 = false;
        docNo = 1;
        encNo = 1;
        outputOpen = false;
        b64 = new B64();
        tempDir = Paths.get(".");
    }

    /**
     * Process VEO separating the document data and the metadata
     *
     * The metadata is copied to a new file. The content of vers:DocumentData is
     * *not* copied unless it is an embedded VEO (i.e. an onion).
     *
     * If extract is true, the document data is extracted to a separate file and
     * the file name is put in the document data element. If extract is false,
     * the document data goes straight to the big bit bucket.
     *
     * This is used in two ways. First, to extract document data for subsequent
     * processing. Second, to reduce the size of the VEO to make it more
     * amenable to processing.
     *
     * If virusScanning is true, the extracted document data is to be tested for
     * viruses. In this case, this method generates two special text files
     * (eicarStart.txt and eicarEnd.txt). These have standard content from EICAR
     * (http://www.eicar.org/86-0-Intended-use.html) that will cause a virus
     * scanner to classify them as a virus and remove them. Two EICAR files are
     * written, one at the beginning of extraction and one at the end. The
     * intent is to confirm (or suggest) that the virus scanner is operational
     * at the beginning of extraction, and is still operational at the end.
     *
     * @param inVeo	the original VEO to pull apart
     * @param outVeo the generated VEO without document data
     * @param tempDir a directory in which to put the extracted content
     * @param useStdDtd
     * @param extract if true extract the document data into files for
     * inspection
     * @param virusScanning if true the extracted document data will be scanned
     * for viruses
     * @throws VEOError if extraction failed
     * @return lists of names of the extracted document data (empty if extract
     * is false)
     */
    public ArrayList<String> extractDocumentData(File inVeo, File outVeo, Path tempDir, boolean useStdDtd, boolean extract, boolean virusScanning)
            throws VEOError {
        FileInputStream fis;
        InputStreamReader isr;
        BufferedInputStream bis;
        FileOutputStream fos;
        OutputStreamWriter osw;

        // check parameters
        if (inVeo == null) {
            throw new VEOError("inVEO must not be null");
        }
        if (outVeo == null) {
            throw new VEOError("outVEO must not be null");
        }

        // remember if to extract (or not)
        extractContent = extract;

        // open input and output streams
        try {
            fis = new FileInputStream(inVeo);
            bis = new BufferedInputStream(fis);
            fos = new FileOutputStream(outVeo);
            osw = new OutputStreamWriter(fos, "UTF-8");
            bw = new BufferedWriter(osw);
        } catch (IOException e) {
            throw new VEOError("Failed opening input and output files: " + e.toString());
        }

        // start the parse
        try {
            if (useStdDtd) {
                sax.parse(bis, this, "http://www.prov.vic.gov.au/vers/standard/");
            } else {
                sax.parse(inVeo, this);
            }
        } catch (SAXException | IOException e) {
            try {
                bis.close();
                fis.close();
                bw.close();
                osw.close();
                fos.close();
            } catch (IOException ioe) {
                /* ignore */
            }
            throw new VEOError("Parse error: " + e.getMessage());
        }

        // close input and output streams
        try {
            bis.close();
            fis.close();
            bw.close();
            osw.close();
            fos.close();
        } catch (IOException ioe) {
            /* ignore */
        }
        return files;
    }

    /**
     * This forces the parser to ignore the reference to the external DTD (if
     * any is present)
     */
    private static final ByteArrayInputStream BAIS = new ByteArrayInputStream("".getBytes());

    @Override
    public InputSource resolveEntity(String name, String publicId, String baseURI, String systemId) throws SAXException {
        return new InputSource(BAIS);
    }

    /**
     * SAX Events captured
     *
     * Start of document... write XML preamble for edited document
     *
     * @throws org.xml.sax.SAXException
     */
    @Override
    public void startDocument() throws SAXException {
        try {
            bw.write("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
            bw.write("<!DOCTYPE vers:VERSEncapsulatedObject SYSTEM \"vers.dtd\">\n");
        } catch (IOException ioe) {
            throw new SAXException("IOException: " + ioe.getMessage());
        }
    }

    /**
     * Start of element
     *
     * Write element and attribute to edited document. Push element and vers:id
     * (if present) onto stack.
     *
     * @param uri
     * @param localName
     * @param qName
     * @param attributes
     * @throws org.xml.sax.SAXException
     */
    @Override
    public void startElement(String uri, String localName,
            String qName, Attributes attributes)
            throws SAXException {
        int i;
        String s;

        // copy element to edited document
        s = null;
        try {
            if (emptyElement) {
                bw.write(">\n");
            }
            bw.write("<" + qName);
            for (i = 0; i < attributes.getLength(); i++) {
                bw.write(" " + attributes.getQName(i) + "=");
                bw.write("\"" + attributes.getValue(i) + "\"");

                // remember vers:id if present
                if (attributes.getQName(i).equals("vers:id")) {
                    s = attributes.getValue(i);
                }
            }
        } catch (IOException ioe) {
            throw new SAXException("IOException: " + ioe.getMessage());
        }

        // push current element name onto stack
        currentElement.push(qName);
        emptyElement = true;
        outputFilename = false;

        // keep track of Documents & Encodings to construct artifical ids
        if (currentElement.peek().equals("vers:VERSEncapsulatedObject")) {
            docNo = 0;
            encNo = 0;
        }
        if (currentElement.peek().equals("vers:Document")) {
            docNo++;
            encNo = 0;
        }
        if (currentElement.peek().equals("vers:Encoding")) {
            encNo++;
            base64 = false;
            fileExt = ".txt";
        }

        // if this DocumentData had a vers:id, use that to name the
        // file, otherwise make up one up
        if (currentElement.peek().equals("vers:DocumentData")) {
            if (s != null) {
                s = s + fileExt;
            } else {
                s = "v1-Revision-1-Document-" + docNo + "-Encoding-" + encNo + "-DocumentData" + fileExt;
            }
            outputFilename = true;
        }

        // push current vers:id onto stack
        currentId.push(s);
    }

    /**
     * Process ignorable whitespace
     *
     * Simply output the whitespace
     */
    /*
     public void ignorableWhitespace(char[] ch, int start, int length)
     throws SAXException {
     int i;

     if (((String) currentElement.peek()).equals("vers:DocumentData")) {
     System.err.println("Ignore...");
     System.err.print("'");
     for (i=start; i<start+length; i++) System.err.print(ch[i]);
     System.err.print("'");
     }
     try {
     for (i=start; i<start+length; i++)
     bw.write(ch[i]);
     } catch (IOException ioe) {
     throw new SAXException("IOException: "+ioe.getMessage());
     }
     }
     */
    /**
     * Processing the content of an element
     *
     * Ignore content that is purely whitespace (shouldn't cause any problems).
     *
     * @param ch
     * @param start
     * @param length
     * @throws org.xml.sax.SAXException
     */
    @Override
    public void characters(char[] ch, int start, int length)
            throws SAXException {
        int i;
        boolean empty;

        // ignore content that is purely whitespace
        empty = true;
        for (i = start; i < start + length; i++) {
            if (ch[i] != ' ' && ch[i] != '\n' && ch[i] != '\r' && ch[i] != '\t') {
                empty = false;
                break;
            }
        }
        if (empty) {
            return;
        }

        // we have content, so this is not an empty element
        try {
            if (emptyElement) {
                bw.write(">");
            }
        } catch (IOException ioe) {
            throw new SAXException("IOException: " + ioe.getMessage());
        }
        emptyElement = false;

        // handle content
        handleContent(ch, start, length);
    }

    /**
     * Handle the content of an XML element
     *
     * Most of the time just output the content, however there is special
     * processing of two elements. The content of vers:DocumentData elements is
     * either suppressed or extracted. The content of vers:RenderingKeywords is
     * examined to see if the vers:DocumentData is base64 encoded and to see
     * what type the file was originally.
     */
    private void handleContent(char[] ch, int start, int length)
            throws SAXException {
        int i;

        // if in vers:DocumentData, suppress or extract content
        if (((String) currentElement.peek()).equals("vers:DocumentData")) {
            if (extractContent) {
                outputDocumentData(ch, start, length);
            } else {
                return;
            }
            return;
        }

        // if in vers:RenderingKeywords, remember the value
        if (((String) currentElement.peek()).equals("vers:RenderingKeywords")) {
            renderingKeywords.append(ch, start, length);
        }

        // output content of element
        try {
            for (i = start; i < start + length; i++) {
                if (ch[i] == '<') {
                    bw.write("&lt;");
                } else if (ch[i] == '>') {
                    bw.write("&gt;");
                } else if (ch[i] == '&') {
                    bw.write("&amp;");
                } else {
                    bw.write(ch[i]);
                }
            }
        } catch (IOException ioe) {
            throw new SAXException("IOException: " + ioe.getMessage());
        }
    }

    /**
     * Output the document data...
     *
     * If we don't have an output file open (i.e. first time this method is
     * called) open the file using the last vers:id attribute as the file name.
     */
    private void outputDocumentData(char[] ch, int start, int length)
            throws SAXException {
        String s;
        Path f;

        // open file to place content (if not already open)
        if (!outputOpen) {

            // open the file for writing... if the content is base64 encoded
            // decode it, otherwise write out the characters
            try {
                s = veoName + "-" + ((String) currentId.peek());
                f = Paths.get(tempDir.toAbsolutePath().toString(), s);
                files.add(s);
                contentfos = new FileOutputStream(f.toFile());
                contentbos = new BufferedOutputStream(contentfos);
                if (!base64) {
                    contentosw = new OutputStreamWriter(contentfos, "8859_1");
                } else {
                    b64.reset();
                }
            } catch (FileNotFoundException e) {
                System.err.println("Could not open file '" + (String) currentId.peek() + "' for writing");
                throw new SAXException("IOException: " + e.getMessage());
            } catch (IOException e) {
                try {
                    contentosw.close();
                } catch (IOException e1) {
                    /* ignore */ }
                try {
                    contentbos.close();
                } catch (IOException e1) {
                    /* ignore */ }
                try {
                    contentfos.close();
                } catch (IOException e1) {
                    /* ignore */ }
                throw new SAXException("IOException: " + e.getMessage());
            }
            outputOpen = true;
        }

        // write characters...
        try {
            if (base64) {
                b64.fromBase64(ch, start, length, contentbos);
            } else {
                contentosw.write(ch, start, length);
            }
        } catch (IOException e) {
            throw new SAXException("IOException: " + e.getMessage());
        }
    }

    /**
     * Output the end of an element
     *
     * @param uri
     * @param localName
     * @param qName
     * @throws org.xml.sax.SAXException
     */
    @Override
    public void endElement(String uri, String localName, String qName)
            throws SAXException {
        String s;
        String[] s1;
        int i;

        // if in vers:RenderingKeywords, extract the keywords
        if (((String) currentElement.peek()).equals("vers:RenderingKeywords")) {

            // get the list of formats. We strip the leading and trailing
            // quotes (if present), and split on either a space or a ';'
            // to handle problem RenderingKeywords
            s = (renderingKeywords.toString()).trim();
            renderingKeywords.setLength(0);
            if (s.charAt(0) == '\'') {
                s = s.substring(1);
            }
            if (s.charAt(s.length() - 1) == '\'') {
                s = s.substring(0, s.length() - 1);
            }
            s1 = s.split("[; ]");

            // look for base64
            base64 = false;
            for (i = 0; i < s1.length; i++) {
                if (s1[i].contains("b64")
                        || s1[i].contains("B64")) {
                    base64 = true;
                }
            }

            // remember last format as file extension. If no '.' at start,
            // add one. Convert MIME formats to normal windows file
            // extensions
            fileExt = s1[s1.length - 1].trim();
            if (fileExt.equals("text/plain")
                    || fileExt.equals(".text/plain")) {
                fileExt = ".txt";
            }
            if (fileExt.equals("text/html")
                    || fileExt.equals(".text/html")) {
                fileExt = ".html";
            }
            if (fileExt.equals("text/xml")
                    || fileExt.equals(".text/xml")) {
                fileExt = ".xml";
            }
            if (fileExt.equals("text/css")
                    || fileExt.equals(".text/css")) {
                fileExt = ".css";
            }
            if (fileExt.equals("text/csv")
                    || fileExt.equals(".text/csv")) {
                fileExt = ".csv";
            }
            if (fileExt.equals("image/tiff")
                    || fileExt.equals(".image/tiff")) {
                fileExt = ".tif";
            }
            if (fileExt.equals("image/jpeg")
                    || fileExt.equals(".image/jpeg")) {
                fileExt = ".jpg";
            }
            if (fileExt.equals("image/jp2")
                    || fileExt.equals(".image/jp2")) {
                fileExt = ".jp2";
            }
            if (fileExt.equals("application/pdf")
                    || fileExt.equals(".application/pdf")) {
                fileExt = ".pdf";
            }
            if (fileExt.equals("application/warc")
                    || fileExt.equals(".application/warc")) {
                fileExt = ".warc";
            }
            if (fileExt.equals("application/msword")
                    || fileExt.equals(".application/msword")) {
                fileExt = ".doc";
            }
            if (fileExt.equals("application/vnd.ms-excel")
                    || fileExt.equals(".application/vnd.ms-excel")) {
                fileExt = ".xls";
            }
            if (fileExt.equals("application/vnd.ms-powerpoint")
                    || fileExt.equals(".application/vnd.ms-powerpoint")) {
                fileExt = ".ppt";
            }
            if (fileExt.equals("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                    || fileExt.equals(".application/vnd.openxmlformats-officedocument.wordprocessingml.document")) {
                fileExt = ".docx";
            }
            if (fileExt.equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    || fileExt.equals(".application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")) {
                fileExt = ".xlsx";
            }
            if (fileExt.equals("application/vnd.openxmlformats-officedocument.presentationml.presentation")
                    || fileExt.equals(".application/vnd.openxmlformats-officedocument.presentationml.presentation")) {
                fileExt = ".pptx";
            }
            if (fileExt.equals("audio/mpeg")
                    || fileExt.equals(".video/mpeg")) {
                fileExt = ".mpg";
            }
            if (fileExt.equals("audio/mpeg4-generic")
                    || fileExt.equals(".video/mpeg4-generic")) {
                fileExt = ".mpg";
            }
            if (fileExt.equals("video/mp4")
                    || fileExt.equals(".video/mp4")) {
                fileExt = ".mp4";
            }
            if (fileExt.equals("video/mpeg")
                    || fileExt.equals(".video/mpeg")) {
                fileExt = ".mp4";
            }
            if (fileExt.equals("message/rfc822")
                    || fileExt.equals(".message/rfc822")) {
                fileExt = ".eml";
            }
            if (fileExt.charAt(0) != '.') {
                fileExt = "." + fileExt;
            }
        }

        // if outputing content of vers:DocumentData element, close output
        if (outputOpen) {
            if (!base64) {
                try {
                    contentosw.close();
                } catch (IOException e1) {
                    /* ignore */ }
            }
            try {
                contentbos.flush();
            } catch (IOException e1) {
                /* ignore */ }
            try {
                contentbos.close();
            } catch (IOException e1) {
                /* ignore */ }
            try {
                contentfos.close();
            } catch (IOException e1) {
                /* ignore */ }
            outputOpen = false;
        }

        // if in a vers:DocumentData element, output the id in lieu of content
        if (!emptyElement && outputFilename) {
            try {
                bw.write((String) currentId.peek());
            } catch (IOException e) {
                throw new SAXException("IOException: " + e.getMessage());
            }
            emptyElement = false;
            outputFilename = false;
        }

        // write the end of the element
        try {
            if (emptyElement) {
                bw.write("/>\n");
            } else {
                bw.write("</" + qName + ">\n");
            }
        } catch (IOException ioe) {
            throw new SAXException("IOException: " + ioe.getMessage());
        }

        // pop element name and vers:id from stack
        currentElement.pop();
        currentId.pop();
        emptyElement = false;
        outputFilename = false;
    }

    /**
     * Main program
     *
     * @param args
     */
    public static void main(String args[]) {
        PullApartVEO pav;
        File veoin, veoout;
        boolean extract;

        if (args.length < 2 || args.length > 3) {
            System.err.println("Useage: VEOCheckII.PullApartVEO -e infile outfile");
            System.exit(-1);
        }
        try {
            if (args.length == 2) {
                extract = false;
                veoin = new File(args[0]);
                veoout = new File(args[1]);
            } else {
                extract = true;
                veoin = new File(args[1]);
                veoout = new File(args[2]);
            }
            pav = new PullApartVEO("Test");
            pav.extractDocumentData(veoin, veoout, Paths.get("."), true, extract, extract);
        } catch (VEOError e) {
            System.err.println(e.getMessage());
        }
    }
}
