import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.AuditResult.auditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import java.io.IOException
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class RegisterScan(private val api: MontoyaApi, private val ciphers: Ciphers, private val tabUI: TabUI): ScanCheck {
    override fun activeAudit(p0: HttpRequestResponse?, p1: AuditInsertionPoint?): AuditResult {
        return auditResult(emptyList())
    }

    override fun passiveAudit(baseRequestResponse: HttpRequestResponse?): AuditResult {
        val detail = StringBuilder("<b>SSl Inspect results: </b>").append("<br>")


        if (baseRequestResponse != null) {
            if(baseRequestResponse.request().path() != "/" ){
                return auditResult(emptyList())
            }
            var ctx = SSLContext.getDefault()
            val targetHost = baseRequestResponse.httpService().host()// Replace with the host you want to scan
            val targetPort = 443 // Default HTTPS port
            ctx = checkCert(ctx,targetHost,targetPort,null,null)
            val sslParams = ctx.supportedSSLParameters

            val workingCiphersSuites = mutableListOf<String>()
            val workingProtocols= mutableListOf<String>()

            for (cipher in sslParams.cipherSuites) {
                try {
                    checkCert(ctx,targetHost, targetPort, cipher,null)
                    workingCiphersSuites.add(cipher)
                } catch (e: IOException) {
                    //println("FAIL $cipher")
                }
            }
            for (protocol in sslParams.protocols) {
                try {
                    checkCert(ctx,targetHost, targetPort, null,protocol)
                    workingProtocols.add(protocol)
                } catch (e: IOException) {
                    //println("FAIL $protocol")
                }
            }

            detail.append("<b>TLS Version: </b>").append("<br>")
            tabUI.addHeaderToTextList("Target:" + baseRequestResponse.request().url())
            for(tls in workingProtocols){
                if(ciphers.deprecated.contains(tls)){
                    detail.append("$tls <b>WEAK</b>").append("<br>")
                    tabUI.addHeaderToTextList("     $tls WEAK")
                }else{
                    detail.append("$tls <b>OK</b>").append("<br>")
                    tabUI.addHeaderToTextList("     $tls OK")
                }
            }
            detail.append("<b>Cipher suites by protocol: </b>").append("<br>")
            val cipherDetailText = CipherParser(api).filterCyphersBold(workingCiphersSuites,workingProtocols,ciphers.ciphers)
            val sortedList = cipherDetailText.sortedWith(compareByDescending<String> { it.split(" ")[1] }
                .thenBy { it.split(" ")[5] })

            sortedList.forEach {
                detail.append(it).append("<br>")
                tabUI.addHeaderToTextList(it.replace("<b>","").replace("</b>",""))
            }


        }
        if(detail.toString() =="<b>SSl Inspect results: </b><br>"){
            return auditResult(emptyList())
        }
        return auditResult(
            listOf(
                AuditIssue.auditIssue(
                    "SSL vulnerabilities",
                    detail.toString(),
                    null,
                    baseRequestResponse?.request()?.url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.CERTAIN,
                    null,
                    null,
                    AuditIssueSeverity.LOW,
                    baseRequestResponse
                )
            )
        )
    }

    private fun checkCert(ctx: SSLContext?, hostname: String?, port: Int, cipher: String?, protocol: String?): SSLContext {
        val socketFactory: SocketFactory = ctx!!.socketFactory
        val socket = socketFactory.createSocket(hostname, port)
        val sslSocket = socket as SSLSocket
        if (cipher != null) sslSocket.enabledCipherSuites = arrayOf(cipher)
        if (protocol != null) sslSocket.enabledProtocols = arrayOf(protocol)
        sslSocket.addHandshakeCompletedListener { }
        sslSocket.startHandshake()
        return ctx
    }

    override fun consolidateIssues(newIssue: AuditIssue?, existingIssue: AuditIssue?): ConsolidationAction {
        return if (existingIssue!!.name().equals(newIssue!!.name()) &&
            existingIssue.detail().equals(newIssue.detail()) &&
            existingIssue.baseUrl().equals(newIssue.baseUrl())
        ) ConsolidationAction.KEEP_BOTH else ConsolidationAction.KEEP_NEW
    }

}