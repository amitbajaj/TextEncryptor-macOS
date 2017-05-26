//
//  ViewController.swift
//  TextEncryptor
//
//  Created by Amit Bajaj on 5/26/17.
//  Copyright © 2017 online.buzzzz.security. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }
    @IBAction func doDecrypt(_ sender: NSButton) {
        debugPrint("Will decrypt data : \((txtData.textStorage?.string)!) using : \(txtPass.stringValue)")
        let ae = AESEncryption();
        let decData:Data?;
        let sourceData:Data? = Data(base64Encoded: (txtData.textStorage?.string)!)!
        let passData:Data? = txtPass.stringValue.data(using: .utf8)
        if sourceData == nil {
            debugPrint("Source data is nil")
            return;
        }
        if passData == nil {
            debugPrint("Pass data is nil")
            return
        }
        do{
            decData = try ae.aesCBCDecrypt(data: sourceData!, keyDataP: passData!)
            if decData != nil{
                txtData.textStorage?.setAttributedString(NSAttributedString(string: String(data: decData!, encoding: .utf8)!))
            }else{
                debugPrint("Error decoding source data!")
            }
        }catch let error{
            debugPrint(error.localizedDescription)
        }

    }

    @IBAction func doEncrypt(_ sender: NSButton) {
        let ae = AESEncryption();
        let encData:Data;
        
        do{
            encData = try ae.aesCBCEncrypt(data: (txtData.textStorage?.string.data(using: String.Encoding.utf8))!, keyDataP: (txtPass.stringValue.data(using: String.Encoding.utf8))!);
            txtData.textStorage?.setAttributedString(NSAttributedString(string: encData.base64EncodedString()))
        }catch let error{
            debugPrint(error.localizedDescription)
        }
    }
    
    @IBOutlet weak var txtPass: NSSecureTextField!


    @IBOutlet var txtData: NSTextView!
}

