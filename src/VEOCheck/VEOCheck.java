/*
 * Copyright Public Record Office Victoria 2005, 2015, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */
package VEOCheck;

/**
 * *************************************************************
 *
 * V E O C H E C K
 *
 * This class checks a VERS2 VEO for validity.
 *
 * Andrew Waugh (andrew.waugh@prov.vic.gov.au) Copyright 2005, 2015, 2018 PROV
 *
 * 20101027 Changed default to be alltests = true to prevent the default from
 * not testing anything (confusing for users) 20150511 Added testing for viruses
 * 20150518 Imported into NetBeans. Altered to support virus checking 20150602
 * Added the ability to specify a directory of VEOs 20180105 Added headless mode
 * for new DA 20180314 Added ability to specify a file that contains the DTD
 * 20180411 Altered virus checking to look for the process rather than the
 * service 20180601 Now uses VERSCommon instead of VEOSupport 20180604
 * Restructured so that DTD would be looked for in a standard place
 *
 *************************************************************
 */
import VERSCommon.VEOError;
import VERSCommon.VEOFatal;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class checks that a VEO is valid. The class checks for (or will check
 * for!) the following:
 * <ul>
 * <li>Conformance to the DTD specified in the DOCTYPE element
 * <li>That the signatures are valid
 * <li>That the public keys are valid
 * <li>That the content can be extracted
 * <li>That content is not infected with viruses
 * </ul>
 * The class will also analyse the VEO for:
 * <ul>
 * <li>The present elements
 * <li>That present elements have legitimate values
 * <li>That there are no empty elements
 * </ul>
 *
 * @author Andrew Waugh
 */
public class VEOCheck {

    // name of this class -- used for exceptions messages
    private static final String CLASS_NAME = "VEOCheck.VEOCheck";

    // mode switch
    private boolean headless; // true if using in headless mode

    // command line arguments
    private final ArrayList<String> files;
    private boolean strict;
    private boolean da;
    private boolean extract;
    private boolean virusCheck;
    private boolean mcafee;
    private int delay;
    private boolean parseVEO;
    private boolean useStdDtd;
    private Path dtd;
    private boolean oneLayer;
    private boolean testSignatures;
    private boolean testValues;
    private boolean version1;
    private boolean version2;
    private boolean verbose;
    private boolean debug;

    // tests
    private ParseVEO parse;
    private TestValues valueTester;
    private TestSignatures signatureTester;
    private TestViruses virusTester;

    // output file
    private Path outputFile;

    // temporary directory
    private Path tempDir;

    // where to write results etc
    private Writer out;

    // logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.VEOCheck");

    /**
     * Constructor for testing as a stand-alone program
     *
     * @param args command line arguments
     * @throws VERSCommon.VEOFatal if processing cannot continue
     */
    public VEOCheck(String args[]) throws VEOFatal {
        // default logging
        LOG.getParent().setLevel(Level.WARNING);
        LOG.setLevel(null);

        headless = false;
        testSignatures = false;
        testValues = false;
        version1 = false;
        version2 = false;
        verbose = false;
        oneLayer = false;
        debug = false;
        strict = false;
        da = false;
        extract = false;
        virusCheck = false;
        mcafee = true;
        delay = 1;
        parseVEO = false;
        useStdDtd = false;
        dtd = null;
        files = new ArrayList<>();
        outputFile = null;
        tempDir = Paths.get(".");

        // process command line args
        parseCommandArgs(args);

        // open output file
        if (outputFile == null) {
            out = new OutputStreamWriter(System.out);
        } else {
            try {
                out = new FileWriter(outputFile.toFile());
            } catch (IOException ioe) {
                throw new VEOFatal("Failed opening output file (" + outputFile.toFile() + "): " + ioe.getMessage());
            }
        }

        // set up environment
        parse = new ParseVEO(verbose, strict, dtd, da, oneLayer, out);
        valueTester = new TestValues(verbose, strict, da, oneLayer, out);
        virusTester = new TestViruses(verbose, strict, da, oneLayer, out);
        signatureTester = new TestSignatures(verbose, false, strict, da, oneLayer, out);

        // print header
        try {
            printHeader();
        } catch (IOException e) {
            throw new VEOFatal("Failed writing header: " + e.getMessage());
        }
    }

    /**
     * Constructor for headless mode.
     *
     * @param dtd the dtd to use to validate the document (null if no
     * validation)
     * @param logLevel logging level (INFO = verbose, FINE = debug)
     */
    public VEOCheck(Path dtd, Level logLevel) {

        // default logging
        LOG.getParent().setLevel(logLevel);
        LOG.setLevel(null);

        // set globals
        headless = true;
        testSignatures = true;
        testValues = true;
        version1 = false;
        version2 = true;
        if (logLevel == Level.FINEST) {
            verbose = true;
            debug = true;
        } else if (logLevel == Level.FINE) {
            verbose = true;
            debug = false;
        } else {
            verbose = false;
            debug = false;
        }
        oneLayer = false;
        strict = false;
        da = false;
        extract = false;
        virusCheck = false;
        mcafee = true;
        delay = 1;
        parseVEO = false;
        useStdDtd = false;
        this.dtd = dtd;
        files = new ArrayList<>();
        outputFile = null;
        tempDir = Paths.get(".");
        out = new StringWriter();

        // set up standard tests...
        parse = new ParseVEO(verbose, strict, this.dtd, da, oneLayer, out);
        valueTester = new TestValues(verbose, strict, da, oneLayer, out);
        virusTester = new TestViruses(verbose, strict, da, oneLayer, out);
        signatureTester = new TestSignatures(verbose, debug, strict, da, oneLayer, out);
    }

    /**
     * Parse command line arguments.
     *
     * Read the command line looking for commands
     * <ul>
     * <li>-all perform all tests
     * <li>-extract extract content from VEO
     * <li>-virus extract content from VEO and check for viruses
     * <li>-d &lt;int&gt; delay before checking for virus removal
     * <li>-eicar use a generic virus test instead of McAfee
     * <li>-strict perform tests according to the standard
     * <li>-da tests customised to what the digital archive will accept
     * <li>-parseVEO don't delete the edited metadata after the run
     * <li>-useStdDtd use DTD from VERS web site
     * <li>-signatures perform tests on signatures
     * <li>-values perform tests on values
     * <li>-out &lt;file&gt; write test results to file
     * <li>-v1.2 force tests for version 1
     * <li>-v2 force tests for version 2
     * <li>-verbose verbose output
     * <li>-oneLayer test only the outer layer
     * <li>-debug output debug information
     * </ul>
     * Any argument that does not begin with a '-' character is assumed to be
     * the name of a VEO to check
     * <p>
     * Virus checking is performed by attempting to write the documents to disc.
     * Modern virus checkers will scan files as they are being staged within the
     * operating system to disc. VEOCheck therefore attempts to write a document
     * to disc and then checks to see if it exists. If the file exists it
     * assumes that the file was not infected. To guard against false negatives
     * (where the file is actually infected, but VEOCheck decides it is not, the
     * following strategies are taken:
     * <ul>
     * <li>Check that the virus checking is actually running. By default, this
     * check is performed by testing if the mcshield service is running. This is
     * the default virus checking software on the PROV computers. Otherwise, if
     * the '-eicar' flag is set, EICAR files are generated and checked that they
     * are removed (you should also see a virus warning message). An EICAR file
     * is a standard file that will be detected and handled as if it was a virus
     * by a virus checking software (it is not, though, a virus). Use of the
     * -eicar option may generate warning logs.
     * <li>A delay is enforced before the existence check is performed. When a
     * file is written to disc it is first created in the directory, then
     * content is written. If it is virus infected, the file will be created but
     * no content will be written and the file will be removed. The delay should
     * be set high enough so that the EICAR file is detected as a virus. (The
     * default is 1 second).
     * </ul>
     *
     * @param args
     * @return
     */
    private void parseCommandArgs(String args[]) throws VEOFatal {
        int i;
        String usage = "VEOCheck [-all] [-strict] [-da] [-extract] [-virus] [-eicar] [-parseVEO] [-useStdDTD] [-dtd <dtdFile>] [-oneLayer] [-signatures] [-values] [-v1.2|-v2] [-virus] [-verbose] [-debug] [-out <file>] [-t <tempDir>] <files>+";

        // not in headless mode...
        headless = false;

        // must have at least one command argument...
        if (args.length == 0) {
            System.err.println("Usage: " + usage);
            System.exit(-1);
        }

        // go through list of command arguments
        for (i = 0; i < args.length; i++) {
            switch (args[i].toLowerCase()) {
                case "-all": // perform all tests
                    testValues = true;
                    virusCheck = true;
                    testSignatures = true;
                    break;
                case "-strict": // test strictly according to the standard
                    strict = true;
                    break;
                case "-da": // test according to what the da will accept
                    da = true;
                    break;
                case "-extract": // extract content and leave it in files
                    extract = true;
                    break;
                case "-virus": // extract content and virus check it
                    extract = true;
                    virusCheck = true;
                    break;
                case "-d": // delay for virus checking
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing integer after '-d'. Usage: " + usage);
                    }
                    delay = Integer.parseInt(args[i]);
                    break;
                case "-eicar": // use the EICAR testing method rather than seeing if the mcshield software is running
                    extract = true;
                    virusCheck = true;
                    mcafee = false;
                    break;
                case "-parseveo": // don't delete the edited metadata after run
                    parseVEO = true;
                    break;
                case "-usestddtd": // use the standard DTD from the web site
                    if (dtd == null) {
                        useStdDtd = true;
                    } else {
                        throw new VEOFatal("Cannot use '-dtd' and '-usestddtd' together");
                    }
                    break;
                case "-dtd": // specify output file
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing dtd file after '-dtd'. Usage: " + usage);
                    }
                    dtd = Paths.get(args[i]);
                    if (useStdDtd) {
                        useStdDtd = false;
                        throw new VEOFatal("Cannot use '-dtd' and '-usestddtd' together");
                    }
                    break;
                case "-signatures": // test signatures in VEO
                    testSignatures = true;
                    break;
                case "-values": // test values in VEO
                    testValues = true;
                    break;
                case "-v1.2": // force version 1.2 or 2.0 processing
                    version1 = true;
                    version2 = false;
                    break;
                case "-v2":
                    version1 = false;
                    version2 = true;
                    break;
                case "-onelayer": // test only the outer layer
                    oneLayer = true;
                    break;
                case "-verbose": // verbose output
                    verbose = true;
                    break;
                case "-debug": // debug output
                    debug = true;
                    break;
                case "-out": // specify output file
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing output file after '-out'. Usage: " + usage);
                    }
                    outputFile = Paths.get(args[i]);
                    break;
                case "-t": // specify a directory in which to put the extracted content
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing temporary directory after '-t'. Usage: " + usage);
                    }
                    tempDir = Paths.get(args[i]);
                    break;
                default: // anything not starting with a '-' is a VEO
                    if (args[i].charAt(0) == '-') {
                        throw new VEOFatal("Unknown argument: '" + args[i] + " Usage: " + usage);
                    } else {
                        files.add(args[i]);
                    }
                    break;
            }
        }
    }

    /**
     * Print header
     *
     * Start of the report contains information about the test tool itself
     *
     * @throws java.io.IOException
     */
    private void printHeader() throws IOException {
        SimpleDateFormat sdf;
        TimeZone tz;

        out.write("******************************************************************************\r\n");
        out.write("*                                                                            *\r\n");
        out.write("*                     V E O   T E S T I N G   T O O L                        *\r\n");
        out.write("*                                                                            *\r\n");
        out.write("*                                Version 2.0                                 *\r\n");
        out.write("*           Copyright 2005, 2015 Public Record Office Victoria               *\r\n");
        out.write("*                                                                            *\r\n");
        out.write("******************************************************************************\r\n");
        out.write("\r\n");

        out.write("Test run: ");
        tz = TimeZone.getTimeZone("GMT+10:00");
        sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss+10:00");
        sdf.setTimeZone(tz);
        out.write(sdf.format(new Date()));
        out.write("\r\n");

        out.write("Testing parameters: ");
        if (extract) {
            out.write("Extract content, ");
        }
        if (testValues) {
            out.write("Test values, ");
        }
        if (testSignatures) {
            out.write("Test signatures, ");
        }
        if (virusCheck) {
            if (mcafee) {
                out.write("Test for viruses using mcafee (delay =" + delay + "), ");
            } else {
                out.write("Test for viruses by generating EICAR files (delay =" + delay + "), ");
            }
        }
        if (oneLayer) {
            out.write("Only test outer layer, ");
        }
        if (version1) {
            out.write("Force test against version 1, ");
        }
        if (version2) {
            out.write("Force test against version 2, ");
        }
        if (strict) {
            out.write("Strict conformance, ");
        }
        if (da) {
            out.write("Digital archive requirement, ");
        }
        if (parseVEO) {
            out.write("Parse original VEO not stripped copy, ");
        }
        if (useStdDtd) {
            out.write("Use standard DTD (http://www.prov.vic.gov.au/vers/standard/vers.dtd), ");
        } else if (dtd != null) {
            out.write("Using DTD '" + dtd.toString() + "', ");
        } else {
            out.write("Using DTDs referenced by SYSTEM attribute in each VEO, ");
        }
        if (tempDir != null) {
            out.write("Extracting to " + tempDir.toString());
        }
        if (verbose) {
            out.write("Verbose output, ");
        }
        if (debug) {
            out.write("Debug output ");
        }
        out.write("\r\n");
        out.write("\r\n");
    }

    /**
     * Test the VEOs
     *
     * Go through the list of files on the command line and run the tests on
     * each VEO. Print the results.
     *
     * @throws VEOError if something failed
     * @throws java.io.IOException
     */
    public void testVEOs() throws VEOError, IOException {
        int i;
        String veo;

        if (headless) {
            return;
        }

        // if a temporary directory is specified, open it (create if necessary)
        if (tempDir != null) {
            if (!Files.exists(tempDir)) {
                try {
                    Files.createDirectory(tempDir);
                } catch (IOException e) {
                    throw new VEOError("Failed creating temporary directory: " + e);
                }
            } else if (!Files.isDirectory(tempDir)) {
                throw new VEOError("Temporary directory " + tempDir.toString() + " already exists but is not a directory");
            }
        } else {
            tempDir = Paths.get(".");
        }

        // check that the virus checking software is running
        checkVirusScannerRunning(tempDir, false);

        // go through the list of VEOs
        for (i = 0; i < files.size(); i++) {
            veo = files.get(i);
            if (veo == null) {
                continue;
            }
            processFile(Paths.get(veo));
        }

        // check that the virus checking software is STILL running
        checkVirusScannerRunning(tempDir, true);
    }

    /**
     * Process directory structure, recursing through subdirectories
     * @param file file being looked at
     * @throws VEOError any error
     */
    private void processFile(Path file) throws VEOError {
        DirectoryStream<Path> ds;
        
        if (Files.isDirectory(file)) {
            try {
                ds = Files.newDirectoryStream(file);
                for (Path p : ds) {
                    processFile(p);
                }
                ds.close();
            } catch (IOException e) {
                throw new VEOError("Failed to process directory '" + file.toString() + "': " + e.getMessage());
            }
        } else {
            try {
                checkVEO(file);
            } catch (IOException e) {
                throw new VEOError(e.toString());
            }
        }
    }

    /**
     * Do the Tests
     *
     * Passed the file that contains the VEO
     */
    private boolean checkVEO(Path file) throws VEOError, IOException {
        org.w3c.dom.Element vdom;
        boolean overallResult;
        PullApartVEO pav;
        ArrayList<String> content;
        Path p, p1;
        String filename;

        if (headless) {
            return (false);
        }

        overallResult = true;
        content = null;
        filename = file.toAbsolutePath().toString();

        out.write("******************************************************************************\r\n");
        
        if (!filename.toLowerCase().endsWith(".veo")) {
            out.write("Ignoring '" + filename + "'\r\n");
            return false;
        }

        out.write("New test. Testing '" + filename + "'\r\n");
        p = Paths.get(filename);
        if (!Files.exists(p)) {
            out.write("  FAILED: VEO does not exist\r\n");
            return false;
        }
        if (!Files.isReadable(p)) {
            out.write("  FAILED: cannot read VEO\r\n");
            return false;
        }

        // first extract the contents of the document data to reduce processing
        if (!parseVEO) {
            pav = new PullApartVEO(filename);
            p1 = null;
            try {
                p1 = Files.createTempFile(Paths.get("."), "Content", ".eveo");
                content = pav.extractDocumentData(p.toFile(), p1.toFile(), tempDir, useStdDtd, extract, virusCheck);
            } catch (VEOError | IOException e) {
                if (p1 != null) {
                    Files.delete(p1);
                }
                out.write("FAILURE: " + e.getMessage() + " (VEOCheck.doTests() ExtractDocumentData)\r\n");
                return false;
            }
        } else {
            p1 = p;
        }

        // first parse the file; if it fails return and stop this test
        if (!parse.performTest(p1.toFile(), dtd, useStdDtd)) {
            if (!parseVEO) {
                Files.delete(p1);
            }
            return false;
        }
        vdom = parse.getDOMRepresentation();

        // perform remaining list of tests...
        if (testValues) {
            if (version1) {
                valueTester.setContext("1.2");
            } else if (version2) {
                valueTester.setContext("2.0");
            }
            overallResult &= valueTester.performTest(vdom);
        } else {
            out.write("Not testing values\r\n");
        }
        if (virusCheck) {
            overallResult &= virusTester.performTest(content, delay);
        } else {
            out.write("Not testing for viruses\r\n");
        }
        if (testSignatures) {
            overallResult &= signatureTester.performTest(p.toFile());
        } else {
            out.write("Not testing signatures\r\n");
        }

        // delete expurgated file
        if (!parseVEO) {
            try {
                Files.delete(p1);
            } catch (IOException ioe) {
                throw new VEOError("Failed deleting: " + ioe.getMessage());
            }
        }

        out.flush();
        return overallResult;
    }

    /**
     * Close output file
     */
    public void closeOutputFile() {
        if (headless) {
            return;
        }
        try {
            out.close();
        } catch (IOException e) {
            /* ignore */ }
    }

    /**
     * Check that the virus scanner is running. Two methods are used. The
     * default is to attempt to write the EICAR file. If this appears in the
     * output directory, either the virus checking software is not running, or
     * is not checking files for viruses as they are written.
     *
     * @param dir directory in which to create the EICAR file
     * @param endOfRun true if checking for the second time at the end of the
     * run
     * @return true if check for virus scanner succeeded
     * @throws VEOError if virus checking failed, IOException if failed to write
     */
    private boolean checkVirusScannerRunning(Path dir, boolean endOfRun) throws VEOError, IOException {
        int i;

        // only perform this check if checking for viruses
        if (!virusCheck) {
            return true;
        }

        // test virus scanner is running
        try {
            if (mcafee) {
                testMcAfee();
            } else {
                generateEICAR(dir, "eicarStart.txt");
            }
        } catch (VEOError | IOException e) {
            throw new VEOError("VIRUS CHECKING FAILED: Content not checked for viruses as " + e.getMessage() + "\n");
        }

        // record the fact that the check was made
        if (!endOfRun) {
            out.write("Virus scanner is operational. Confirm that it is still operational at end of run.\n");
        } else {
            for (i = 0; i < 79; i++) {
                out.write('*');
            }
            out.write("\r\n");
            out.write("Virus scanner is still operational at end of run. Virus checks are valid.\n");
        }
        return true;
    }

    /**
     * Test to see if this computer has McAfee installed and the server is
     * running. The approach taken is by attempting to start the McAfee mcshield
     * service, and checking to see if the response is that it is actually
     * running. Advice from McAfee is that if the service is running it will
     * detect infected documents as they are written to disk.
     *
     * @return true if the test succeeded
     * @throws IOException
     */
    static String exe = "mcshield.exe";
    static String cmd = "tasklist /fi \"imagename eq " + exe + "\" /nh";

    private void testMcAfee() throws IOException, VEOError {
        int res;
        Runtime rt;
        Process proc;
        InputStream stderr, output;
        InputStreamReader isr;
        BufferedReader br;
        String line;
        boolean mcAfeeRunning;

        res = -1;
        mcAfeeRunning = false;

        // attempt to start the mcshield service 
        rt = Runtime.getRuntime();
        try {
            proc = rt.exec(cmd);
        } catch (IOException e) {
            throw new VEOError("Couldn't execute command to confirm McAfee is running (" + cmd + "): " + e.toString());
        }

        // drain the standard out looking for the specified process 
        output = proc.getInputStream();
        isr = new InputStreamReader(output);
        br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            // System.out.println("lo:" + line); 
            if (line.contains(exe)) {
                mcAfeeRunning = true;
            }
        }
        try {
            br.close();
            isr.close();
        } catch (IOException e) {
            /* ignore */ }

        // drain stderr of the underlying process to prevent blocking 
        stderr = proc.getErrorStream();
        isr = new InputStreamReader(stderr);
        br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            // System.out.println("le:" + line); 
        }
        try {
            br.close();
            isr.close();
        } catch (IOException e) {
            /* ignore */ }

        // wait for process to terminate
        try {
            res = proc.waitFor();
        } catch (InterruptedException e) {
            throw new VEOError("Checking McAfee service was interupted (" + cmd + "): " + e.toString());
        }
        // out.write("Exec: '" + cmd + "' returned: " + res + " McAfee Running: " + mcAfeeRunning + "\n"); 
        if (!mcAfeeRunning) {
            throw new VEOError("McAfee virus scanner is NOT running. Returned: " + res + "\n");
        }
    }

    /**
     * Generate a file containing the EICAR content. This content will be (or
     * should be) detected by a virus scanner as a virus and handled.
     *
     * @param dir directory in which to create the EICAR file
     * @param file name to create
     * @throws VEOError if a failure occurred when creating the EICAR file
     */
    private void generateEICAR(Path dir, String file) throws VEOError {
        Path eicar;
        FileOutputStream fos;
        OutputStreamWriter osw;

        // test for eicar.txt file and remove if present
        eicar = Paths.get(dir.toString(), file);
        if (Files.exists(eicar)) {
            try {
                Files.delete(eicar);
            } catch (IOException ioe) {
                throw new VEOError("Failed to delete '" + eicar.toString() + "':" + ioe.toString());
            }
        }

        // try to create eicar.txt file
        try {
            fos = new FileOutputStream(eicar.toFile());
        } catch (FileNotFoundException e) {
            throw new VEOError("Failed to create '" + eicar.toString() + "': " + e.toString());
        }
        osw = new OutputStreamWriter(fos);
        try {
            osw.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        } catch (IOException e) {
            throw new VEOError("Failed in writing to '" + eicar.toString() + "': " + e.toString());
        }
        try {
            osw.close();
        } catch (IOException e) {
            throw new VEOError("Failed in closing osw in '" + eicar.toString() + "': " + e.toString());
        }
        try {
            fos.close();
        } catch (IOException e) {
            throw new VEOError("Failed in closing fos in '" + eicar.toString() + "': " + e.toString());
        }

        // delay to give virus checker time to work
        try {
            TimeUnit.SECONDS.sleep(delay);
        } catch (InterruptedException e) {
            /* ignore */
        }

        // check that virus checker removed first EICAR file
        if (Files.exists(eicar)) {
            throw new VEOError("Virus checker did not remove '" + eicar.toString() + "'. Virus checking is consequently not effective. This indicates virus checker is either not running or not detecting creation of virus infected files");
        }
    }

    /**
     * Test a single VEO in headless mode
     *
     * @param veo the original VEO including document content
     * @param cutVEO cut down VEO with document content removed
     * @param out a StringWriter to capture output
     * @return true if test was successful
     * @throws VEOSupport.VEOError
     */
    public boolean vpaTestVEO(Path veo, Path cutVEO, StringWriter out) throws VEOError {
        org.w3c.dom.Element vdom;
        boolean overallResult;

        if (!headless) {
            return false;
        }
        tempDir = Paths.get("."); // temporary directory
        overallResult = true;
        parse.setOutput(out);
        valueTester.setOutput(out);
        virusTester.setOutput(out);
        signatureTester.setOutput(out);

        if (!Files.exists(veo)) {
            throw new VEOError("  FAILED: VEO does not exist\r\n");
        }
        if (!Files.isReadable(veo)) {
            throw new VEOError("  FAILED: cannot read VEO\r\n");
        }

        // first parse the file; if it fails return and stop this test
        if (!parse.performTest(cutVEO.toFile(), dtd, useStdDtd)) {
            return false;
        }
        vdom = parse.getDOMRepresentation();

        // perform remaining list of tests...
        if (testValues) {
            if (version1) {
                valueTester.setContext("1.2");
            } else if (version2) {
                valueTester.setContext("2.0");
            }
            overallResult &= valueTester.performTest(vdom);
        }
        /*
        if (virusCheck) {
            overallResult &= virusTester.performTest(content, delay);
        }
         */
        if (testSignatures) {
            overallResult &= signatureTester.performTest(veo.toFile());
        }
        return overallResult;
    }

    /**
     * Main program.
     *
     * @param args command line arguments
     */
    public static void main(String args[]) {
        VEOCheck vc;

        try {
            vc = new VEOCheck(args);
            vc.testVEOs();
            vc.closeOutputFile();
        } catch (IOException | VEOError e) {
            System.err.println(e.toString());
            System.exit(-1);
        }
    }
}
