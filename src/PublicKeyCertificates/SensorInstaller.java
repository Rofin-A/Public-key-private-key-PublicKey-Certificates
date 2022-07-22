/**
 * @classname: ChiefSensorInstaller.Java
 * @author: Rofin A
 */
/*----------------------------------------------------------------------------- 
*  Purpose: This class is created to instantiate installers in the 
*  InstallerServer.Java Class. Based on the instance, installers authorization 
*  for relocating the sensor will be assesed
-------------------------------------------------------------------------------*/
package PublicKeyCertificates;

public abstract class SensorInstaller {
// ---------------------Global Variables------------------------   
    String userid;
    String password;
    String salt;
// --------------------------Constructor------------------------
    SensorInstaller(String userid,String password,String salt){
        this.userid = userid;
        this.password = password;
        this.salt = salt;
    }
}
