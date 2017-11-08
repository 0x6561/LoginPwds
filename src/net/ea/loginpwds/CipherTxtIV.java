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
package net.ea.loginpwds;

public class CipherTxtIV
{
 private String cipherText;
private String iv; 

public CipherTxtIV()
{
  cipherText = "";
  iv = "";
}

public CipherTxtIV(String c, String i)
{
  cipherText = c;
  iv = i;
}

public void setCipherTxt(String c)
{
  cipherText = c;
}

public void setIV(String i)
{
  iv = i;
}

public String getCipherTxt()
{
  return cipherText;
}

public String getIV()
{
  return iv;
}

}
