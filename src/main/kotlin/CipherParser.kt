import burp.api.montoya.MontoyaApi

class CipherParser(val api: MontoyaApi) {

    val ciphers = mutableMapOf<String,String>()


    init {
        val classLoader = javaClass.classLoader
        val resourceStream = classLoader.getResourceAsStream("ciphers/cipher-mapping.txt")

        if (resourceStream != null) {
            val file = resourceStream.bufferedReader().use { it.readText() }
            val lines = file.lines()
            println(lines)
            for (line in lines) {
                val tokens = line.split("\\s+".toRegex()).filter { it.isNotBlank() }

                if (tokens.size >= 2) {
                    val cipherName = tokens[3]
                    val protocol = tokens[4]
                    ciphers[cipherName] = protocol
                }
            }
        }
    }


    fun filterCyphersBold(supportedCiphers: MutableList<String>, supportedProtocols: MutableList<String>, strongCiphers: List<String>):List<String>{
        val text = mutableListOf<String>()
        supportedCiphers.forEach {
            if(ciphers.containsKey(it)){
                if(supportedProtocols.contains(ciphers[it])){
                    if(strongCiphers.contains(it)){
                        text.add("Protocol: ${ciphers[it]} Cipher Name: $it <b>OK</b>")
                    }else{
                        text.add("Protocol: ${ciphers[it]} Cipher Name: $it <b>WEAK</b>")
                    }
                }
            }
        }
        return text
    }

}