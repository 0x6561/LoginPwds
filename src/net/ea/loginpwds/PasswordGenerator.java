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
import java.util.List;
import java.util.ArrayList;
import java.security.SecureRandom;
import java.util.Locale;

public class PasswordGenerator
{
  private static List<String> pwd;

  private static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String lower = upper.toLowerCase(Locale.ROOT);
  private static final String digits = "0123456789";
  private static final String punctuation = ".,;:'{}()_-+*#@%^&/'\\\"|!=";
  private static final String upperalphanum = upper +  digits;
  private static final String loweralphanum = lower + digits;
  private static final String alphanum = upper + lower + digits;
  private static final String all = alphanum + punctuation;
  private static SecureRandom random;

  public PasswordGenerator()
  {
    random = new SecureRandom();
    pwd = new ArrayList<String>();

  } 

  public void addCharsUpper(int numChars)
  {
    char[] symbols = upper.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsLower(int numChars)
  {
    char[] symbols = lower.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsDigits(int numChars)
  {
    char[] symbols = digits.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsPunctuation(int numChars)
  {
    char[] symbols = punctuation.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsUpperAlphaNum (int numChars)
  {
    char[] symbols = upperalphanum.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsLowerAlphaNum (int numChars)
  {
    char[] symbols = loweralphanum.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsAlphaNum (int numChars)
  {
    char[] symbols = alphanum.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  public void addCharsAll(int numChars)
  {
    char[] symbols = all.toCharArray();
    char[] buf = new char[numChars];
    for (int i = 0; i < buf.length; ++i)
      buf[i] = symbols[random.nextInt(symbols.length)];
    pwd.add(new String(buf));
  }

  // remove last chunk
  public void removeLast()
  {
    pwd.remove(pwd.size()-1);
  }

  public void reset()
  {
    pwd.clear();
  }

  //get pwd
  public String getPassword()
  {
    String pw = "";
    for(String s : pwd)
    {
      pw += s;
    }
    //return pwd.toString();
    return pw;
  }

  public String toString()
  {
    return getPassword();
  }
}
