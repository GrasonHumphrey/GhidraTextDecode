/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidratextdecode;

import java.awt.BorderLayout;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.apache.commons.dbcp2.managed.TransactionContextListener;

import aQute.bnd.header.Attrs.DataType;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.jar.ResourceFile;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.cmd.data.*;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pcodeCPort.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Decodes text to arrays",
	description = "Decodes text to arrays."
)
//@formatter:on
public class GhidraTextDecodePlugin extends ProgramPlugin {

	//MyProvider provider;
	private DockingAction decodeToCommentAction;
	private DockingAction decodeToLabelAction;
	private DockingAction decodeDontStopAction;
	private DockingAction decodeDontStopCommentAction;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public void DecodeText (Boolean setComment, Boolean stopOnUnknown) {
		//Msg.info(this, currentSelection.toString());
		// Start transaction
		var id = currentProgram.startTransaction("Text Decode Transaction");
		
		if (currentSelection.getNumAddresses() == 0) {
			// Nothing selected
			currentProgram.endTransaction(id, true);
			return;
		}
		
		
		
		// Try to load dictionary
		ResourceFile resFile = null;
		try {
			resFile =Application.getModuleDataFile("DecodeDictionary.txt");
		} catch (Exception e) {
			Msg.error(GhidraTextDecodePlugin.class, "Could not find path to DecodeDictionary.txt", e);
			currentProgram.endTransaction(id, true);
			return;
		} 
		if (resFile == null) {
			Msg.error(GhidraTextDecodePlugin.class, "Could not find file DecodeDictionary.txt");
			currentProgram.endTransaction(id, true);
			return;
		}
		
		// Read lines from dictionary
		File file = resFile.getFile(isDisposed());
		FileReader fileReader = null;
		try {
			fileReader = new FileReader(file);
		} catch (Exception e) {
			Msg.error(GhidraTextDecodePlugin.class, "Could not convert DecodeDictionary.txt resourceFile to file");
		}
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		List<String> lines = new ArrayList<String>();
		try {
			String line;
			while ((line = bufferedReader.readLine()) != null) {
			    lines.add(line);
			}
		} catch (Exception e) {
			Msg.error(GhidraTextDecodePlugin.class, "Could not read lines from DecodeDictionary.txt");
		}
        try {
			bufferedReader.close();
		} catch (Exception e) {
			Msg.error(GhidraTextDecodePlugin.class, "Could not close DecodeDictionary.txt");
		}
        
        // Convert lines read to translator array
        ArrayList<String> encodedDict = new ArrayList<String>();
        ArrayList<String> decodedDict = new ArrayList<String>();
        for (String line : lines) {
        	//Msg.info(GhidraNESTextDecodePlugin.class, line);
        	if (line.length() > 0) {
	        	if (line.charAt(0) != '#') {
	        		String[] parts = line.split("=");
	        		if (parts.length != 2) {
	        			Msg.error(GhidraTextDecodePlugin.class, "Skipping bad entry in DecodeDictionary.txt: " + line);
	        			continue;
	        		}
	        		encodedDict.add(parts[0].toLowerCase());
	        		decodedDict.add(parts[1]);
	        	}
        	}
        }
        
        // Do translation
        var listing = currentProgram.getListing();
        listing.clearCodeUnits(currentSelection.getMinAddress(), currentSelection.getMaxAddress(), false);
        
        String decodedStr = "";
        ghidra.program.model.address.Address startAddress = currentSelection.getMinAddress();
        ByteDataType byteDataType = new ByteDataType();
        int arraySize = 0;
        for (ghidra.program.model.address.Address address : currentSelection.getAddresses(currentSelection.getMinAddress(), true)) {
        	String encodedData = "";
			try {
				encodedData = String.format("%02X", listing.getDataAt(address).getByte(0) & 0xFF).toLowerCase();
			} catch (Exception e) {
				Msg.error(GhidraTextDecodePlugin.class, "Error converting data to string");
			}
        	//Msg.info(GhidraNESTextDecodePlugin.class, encodedData);
        	int dictIndex = encodedDict.indexOf(encodedData);
        	if (dictIndex < 0) {
        		if (stopOnUnknown) {
        			Msg.error(GhidraTextDecodePlugin.class, "Unknown encoded symbol: " + encodedData + " at address: " + address.toString());
	        		currentProgram.endTransaction(id, true);
	        		return;
        		}
        		Msg.info(GhidraTextDecodePlugin.class, "Unknown encoded symbol: " + encodedData + " at address: " + address.toString());
        		decodedStr += '?';
        		arraySize += 1;
        	} else {
				String decodedData = decodedDict.get(dictIndex);
				//Msg.info(GhidraTextDecodePlugin.class, decodedData);
				if (decodedData.equals("<END>")) {
					if (arraySize > 0) {
						arraySize += 1;
						// Set comment
						//Msg.info(GhidraTextDecodePlugin.class, decodedStr);
						if (setComment) {
							listing.setComment(startAddress, CodeUnit.PLATE_COMMENT, decodedStr);
						}
						// Create array 
						CreateArrayCmd cmd = new CreateArrayCmd(startAddress, arraySize, byteDataType, byteDataType.getLength());
						cmd.applyTo(currentProgram);
						// Add label
						AddLabelCmd labelCmd = new AddLabelCmd(startAddress, "STR_" + decodedStr, SourceType.ANALYSIS);
						labelCmd.applyTo(currentProgram);
						
						decodedStr = "";
						arraySize = 0;
						startAddress = address.add(1);
					} else {
						startAddress = address.add(1);
						decodedStr = "";
						arraySize = 0;
					}
				} else {
					decodedStr += decodedData;
					arraySize += 1;
					}
	        	}	
	        }
		
		// End transaction
		currentProgram.endTransaction(id, true);
	}
	
	public GhidraTextDecodePlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		//String pluginName = getName();
		//provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		//String topicName = this.getClass().getPackage().getName();
		//String anchorName = "HelpAnchor";
		//provider.setHelpLocation(new HelpLocation(topicName, anchorName));
		
		
		// Create the decode action.
		decodeToLabelAction = new DockingAction("Text Decode", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				DecodeText(false, true);
			}
		};
		
		decodeToCommentAction = new DockingAction("Text Decode", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				DecodeText(true, true);
			}
		};
		
		decodeDontStopAction = new DockingAction("Text Decode", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				DecodeText(false, false);
			}
		};
		
		decodeDontStopCommentAction = new DockingAction("Text Decode", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				DecodeText(true, false);
			}
		};
		
		decodeToLabelAction.setEnabled(true);
		decodeToLabelAction.setPopupMenuData(new MenuData(new String[] { "Text Decode", "Decode" }));
		tool.addAction(decodeToLabelAction);
		
		decodeToCommentAction.setEnabled(true);
		decodeToCommentAction.setPopupMenuData(new MenuData(new String[] { "Text Decode", "Decode w/ comments" }));
		tool.addAction(decodeToCommentAction);
		
		decodeDontStopAction.setEnabled(true);
		decodeDontStopAction.setPopupMenuData(new MenuData(new String[] { "Text Decode", "Force decode" }));
		tool.addAction(decodeDontStopAction);
		
		decodeDontStopCommentAction.setEnabled(true);
		decodeDontStopCommentAction.setPopupMenuData(new MenuData(new String[] { "Text Decode", "Force decode w/ comments" }));
		tool.addAction(decodeDontStopCommentAction);

	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	// If provider is desired, it is recommended to move it to its own file
	/*
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), "Skeleton Provider", owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
	*/
}
