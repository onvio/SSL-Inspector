import burp.api.montoya.MontoyaApi
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

class Ciphers(val api:MontoyaApi) {

    var ciphers = mutableListOf<String>()
    var deprecated = mutableListOf<String>()
    var ciphers_json = ""
    init {
        val folder = Paths.get("files/default_ciphers.json")
        if (Files.exists(folder)) {
            loadFromFile()
        }else{
            loadFromDefault()
        }


    }


    fun saveToFile(){
        // Create the folder if it doesn't exist
        val folder = Paths.get("files")
        if (!Files.exists(folder)) {
            Files.createDirectories(folder)
        }
        // Create the file path
        val filePath = folder.resolve("default_ciphers.json")
        // Write the JSON to the file
        Files.write(filePath, ciphers_json.toByteArray())
    }

    fun loadFromFile(){

        val filePath = "files/default_ciphers.json"
        val file = File(filePath)

        if (file.exists()) {
            try {
                val fileContents = file.readText()
                readFromJson(fileContents)
            } catch (e: Exception) {
                api.logging().logToOutput("Error reading the file: ${e.message}")
            }
        } else {
            api.logging().logToOutput("File does not exist: $filePath")
        }

    }

    fun loadFromDefault(){
        val classLoader = javaClass.classLoader
        val resourceStream = classLoader.getResourceAsStream("ciphers/default_ciphers.json")
        if (resourceStream != null) {
            val json = resourceStream.bufferedReader().use {txt -> txt.readText() }
            readFromJson(json)
        }

    }


    fun readFromJson(json: String){
        ciphers_json = json
        val jsonData = JSONObject(json)
        // Access the "headers" array
        val cipherArray = jsonData.getJSONArray("ciphers")

        if (cipherArray != null) {
            for (i in 0..<cipherArray.length()) {
                val requiredHeader = cipherArray.getString(i)
                ciphers.add(requiredHeader)
            }
        }

        // Access the "deprecated" array
        val deprecatedArray = jsonData.optJSONArray("deprecated")
        if (deprecatedArray != null) {
            for (i in 0..<deprecatedArray.length()) {
                val deprecatedHeader = deprecatedArray.getString(i)
                deprecated.add(deprecatedHeader)
            }
        }

    }

}
