import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

class Burp: BurpExtension {
    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }
        val ciphers = Ciphers(api)
        val tabUI = TabUI(api,ciphers)
        api.extension().setName("SSL Inspector")
        api.logging().logToOutput("Starting!!!!")
        api.scanner().registerScanCheck(RegisterScan(api,ciphers,tabUI))
        api.userInterface().registerSuiteTab("SSL Inspector",tabUI)
    }
}