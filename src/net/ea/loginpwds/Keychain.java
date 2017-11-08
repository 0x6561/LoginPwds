/**

   © Copyright 2017 Edgar Aguiniga ©
   This file is part of LoginPwds.

   LoginPwds is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   LoginPwds is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LoginPwds.  If not, see <http://www.gnu.org/licenses/>.

 **/
//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2017.11.03 at 05:58:15 AM MST 
//


package net.ea.loginpwds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="keychain_owner" type="{}keychain_owner"/>
 *         &lt;element name="cipher_info" type="{}cipher_info"/>
 *         &lt;element name="keyring" type="{}keyring"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "keychainOwner",
    "cipherInfo",
    "keyring"
})
@XmlRootElement(name = "keychain")
public class Keychain {

    @XmlElement(name = "keychain_owner", required = true)
    protected KeychainOwner keychainOwner;
    @XmlElement(name = "cipher_info", required = true)
    protected CipherInfo cipherInfo;
    @XmlElement(required = true)
    protected Keyring keyring;

    /**
     * Gets the value of the keychainOwner property.
     * 
     * @return
     *     possible object is
     *     {@link KeychainOwner }
     *     
     */
    public KeychainOwner getKeychainOwner() {
        return keychainOwner;
    }

    /**
     * Sets the value of the keychainOwner property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeychainOwner }
     *     
     */
    public void setKeychainOwner(KeychainOwner value) {
        this.keychainOwner = value;
    }

    /**
     * Gets the value of the cipherInfo property.
     * 
     * @return
     *     possible object is
     *     {@link CipherInfo }
     *     
     */
    public CipherInfo getCipherInfo() {
        return cipherInfo;
    }

    /**
     * Sets the value of the cipherInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link CipherInfo }
     *     
     */
    public void setCipherInfo(CipherInfo value) {
        this.cipherInfo = value;
    }

    /**
     * Gets the value of the keyring property.
     * 
     * @return
     *     possible object is
     *     {@link Keyring }
     *     
     */
    public Keyring getKeyring() {
        return keyring;
    }

    /**
     * Sets the value of the keyring property.
     * 
     * @param value
     *     allowed object is
     *     {@link Keyring }
     *     
     */
    public void setKeyring(Keyring value) {
        this.keyring = value;
    }

}
