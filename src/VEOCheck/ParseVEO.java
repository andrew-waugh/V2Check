/*
 * Copyright Public Record Office Victoria 2005, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */
package VEOCheck;

/**
 * *************************************************************
 *
 * P A R S E V E O
 *
 * This class tests a VEO for conformance to a DTD. As a side effect, the VEO is
 * parsed into DOM for subsequent tests and we work out the version.
 *
 * 20180314 Added code to read vers.dtd from a standard location 20150518
 * Imported into NetBeans. 20180314 Altered so that caller can specify a DTD
 * file
 *
 * Andrew Waugh Copyright 2005 PROV
 *
 *************************************************************
 */
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.w3c.dom.*;

public class ParseVEO extends TestSupport {

    private final static Logger LOG = Logger.getLogger("VEOCheck.ParseVEO");

    // internal (DOM) representation of VEO being tested
    private Element doc;

    // parser
    private DocumentBuilder db;

    // stated version of this veo
    String version;

    /**
     * Default constructor
     *
     * @param verbose true if give more information in the result
     * @param strict true if enforce strict compliance to VERS standard
     * @param dtd DTD file to use (null if use the one referenced by the VEO)
     * @param da
     * @param oneLayer true if only check outer layer of a modified DA
     * @param out StringBuilder to capture results of test
     */
    public ParseVEO(boolean verbose, boolean strict,
            Path dtd, boolean da, boolean oneLayer, Writer out) {
        super(verbose, strict, da, oneLayer, out);

        DocumentBuilderFactory dbf;

        doc = (Element) null;

        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setValidating(true);
        /*
         dbf.setIgnoringComments(false);
         dbf.setIgnoringElementContentWhitespace(true);
         dbf.setCoalescing(true);
         dbf.setExpandEntityReferences(true);
         */

        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException pce) {
            /* ignore */ }

        // Set error handler...
        db.setErrorHandler(new XMLParserErrorHandler());

        // Force the reading of the DTD from the file specified. This is called
        // when the parser needs to resolve an external entity. We check that
        // the external entity is actually 'vers.dtd', and, if so, return a
        // reader associated with the specified DTD.
        // According to InputSource manual, standard handling is to close the
        // inputsource and reader upon completion of parsing
        db.setEntityResolver((String publicId, String systemId) -> {
            if (dtd != null && systemId.contains("vers.dtd")) {
                return new InputSource(new FileReader(dtd.toFile()));
            } else {
                return null;
            }
        });

        version = null;
    }

    /**
     *
     * Return the name of this test
     *
     * @return the name of the test
     */
    @Override
    public String getName() {
        return "ParseVEO";
    }

    /**
     * Return the notional version
     *
     * @return get the calculated version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Parses the VEO, checking for conformance to the DTD.
     *
     * @param f file containing the VEO
     * @param dtd file containing the DTD to validate against
     * @param useStdDtd if true, use the DTD from the web site
     * @return true if parse suceeded
     *
     * ajw 20060809 Added information in error message to ensure user thinks
     * about connecting to the network when using -useStdDtd
     */
    public boolean performTest(File f, Path dtd, boolean useStdDtd) {
        NodeList nl;
        Node n;
        Document d;
        FileInputStream fis;
        BufferedInputStream bis;
        InputSource is;

        printTestHeader("Parsing VEO");

        // parse the input file
        bis = null;
        fis = null;
        try {
            fis = new FileInputStream(f);
            bis = new BufferedInputStream(fis);
            is = new InputSource(bis);
            if (useStdDtd) {
                d = db.parse(bis, "http://www.prov.vic.gov.au/vers/standard/");
            } else {
                d = db.parse(is);
            }
            doc = d.getDocumentElement();
            bis.close();
            fis.close();
        } catch (IOException e) {
            failed("IOException when parsing document: " + e.getMessage()
                    + ". Note: if -useStdDtd command line option is being "
                    + "used, the computer must be connected to the network.");
            return false;
        } catch (SAXException e) {
            failed("SAXException when parsing document: " + e.getMessage());
            return false;
        } finally {
            try {
                if (bis != null) {
                    bis.close();
                }
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                /* ignore */
            }
        }

        // normalise document
        doc.normalize();

        // find version attribute
        nl = doc.getElementsByTagName("vers:Version");
        if (nl.getLength() == 0) {
            version = null;
            return false;
        }
        n = nl.item(0);
        if (n.getNodeType() != Node.ELEMENT_NODE) {
            LOG.log(Level.WARNING, "*****PANIC in VEOCheck.ParseVEO.performTest(): Cannot find vers:Version element");
            version = null;
            return false;
        }
        version = getValue(n);
        return true;
    }

    /**
     * Get the parsed document as a DOM representation
     *
     * @return
     */
    public Element getDOMRepresentation() {
        return doc;
    }

    // Error handler to report errors and warnings
    private static class XMLParserErrorHandler implements ErrorHandler {

        XMLParserErrorHandler() {
        }

        /**
         * Returns a string describing parse exception details
         */
        private String getParseExceptionInfo(SAXParseException spe) {
            String systemId, info;

            systemId = spe.getSystemId();
            if (systemId == null) {
                systemId = "null";
            }
            info = "URI=" + systemId
                    + " Line=" + spe.getLineNumber()
                    + ":" + spe.getMessage();
            return info;
        }

        /**
         * Standard SAX Error handlers
         */
        @Override
        public void warning(SAXParseException spe) throws SAXException {
            /* ignore */
        }

        @Override
        public void error(SAXParseException spe) throws SAXException {
            String msg = "Error: " + getParseExceptionInfo(spe);
            throw new SAXException(msg);
        }

        @Override
        public void fatalError(SAXParseException spe) throws SAXException {
            String msg = "Fatal Error: " + getParseExceptionInfo(spe);
            throw new SAXException(msg);
        }
    }
}
