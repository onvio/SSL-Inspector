import burp.api.montoya.MontoyaApi
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.io.IOException
import javax.swing.*
import javax.swing.filechooser.FileNameExtensionFilter


class TabUI(val api: MontoyaApi, val ciphers: Ciphers): JPanel() {

    private val listModel = DefaultListModel<String>()
    private val textArea = JTextArea(10, 40)
    init {
        this.layout = BorderLayout()

        val panel1 = JPanel()
        panel1.layout = BoxLayout(panel1, BoxLayout.PAGE_AXIS)

        val title = JLabel("SSL Inspector")
        title.alignmentX = Component.CENTER_ALIGNMENT
        panel1.add(title)


        val buttonPanel = JPanel()
        buttonPanel.layout = FlowLayout(FlowLayout.CENTER)
        val importButton = JButton("Import JSON file")
        importButton.addActionListener{ _ -> chooseAndReplaceJSON() }
        buttonPanel.add(importButton)
        val exportButton = JButton("Export results to clipboard")

        buttonPanel.add(exportButton)
        panel1.add(buttonPanel)

        val panel2 = JPanel()
        panel2.layout = BorderLayout()

        val textList = JList(listModel)
        val scrollPane = JScrollPane(textList)
        panel2.add(scrollPane, BorderLayout.CENTER)

        // Export all list values to clipboard
        exportButton.addActionListener {
            val clipboard = Toolkit.getDefaultToolkit().systemClipboard
            val textToCopy = listModel.elements().asSequence().joinToString("\n")
            val stringSelection = StringSelection(textToCopy)
            clipboard.setContents(stringSelection, null)
        }

        val panel3 = JPanel()
        panel3.layout = BorderLayout()

        textArea.lineWrap = true
        textArea.wrapStyleWord = true
        val scrollPaneTextArea = JScrollPane(textArea)
        panel3.add(scrollPaneTextArea, BorderLayout.CENTER)

        val footerPanel = JPanel()
        footerPanel.layout = FlowLayout(FlowLayout.RIGHT)
        val saveButton = JButton("Save")
        saveButton.addActionListener{
            ciphers.readFromJson(textArea.text)
            ciphers.saveToFile()
        }
        footerPanel.add(saveButton)
        val loadDefaultButton = JButton("Loadin Default")
        loadDefaultButton.addActionListener {
            ciphers.loadFromDefault()
            ciphers.saveToFile()
            setTextArea()
        }
        footerPanel.add(loadDefaultButton)
        panel3.add(footerPanel, BorderLayout.SOUTH)

        this.add(panel1, BorderLayout.WEST)
        this.add(panel2, BorderLayout.CENTER)
        this.add(panel3, BorderLayout.EAST)

        this.isVisible = true
        setTextArea()
    }

    private fun setTextArea(){
        textArea.text = ciphers.ciphers_json
    }

    private fun chooseAndReplaceJSON() {
        val fileChooser = JFileChooser()
        val jsonFilter = FileNameExtensionFilter("JSON files","json")
        fileChooser.addChoosableFileFilter(jsonFilter)
        val returnValue = fileChooser.showOpenDialog(null)
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            val selectedFile = fileChooser.selectedFile
            try {
                ciphers.readFromJson(selectedFile.readText())
                ciphers.saveToFile()
                setTextArea()
            } catch (e: IOException) {
                e.printStackTrace()
                api.logging().logToOutput("Failed to replace the JSON file.")
            }
        }
    }

    fun addHeaderToTextList(text: String){
        listModel.addElement(text)
    }







}

