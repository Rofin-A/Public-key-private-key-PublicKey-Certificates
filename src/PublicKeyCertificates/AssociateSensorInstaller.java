/**
 * @classname: AssociateSensorInstaller.java
 * @author: Rofin A
 */
/*----------------------------------------------------------------------------- 
*  Purpose: This class is created to intantiate Associate Sensor installers
*  in the InstallerServer.Java Class. Based on the instance the installers 
*  authorization for relocating the sensor will be assesed
-------------------------------------------------------------------------------*/
package PublicKeyCertificates;

public class AssociateSensorInstaller extends SensorInstaller{
    // --------------------------Constructor------------------------
    public AssociateSensorInstaller(String userid, String passowrd,String salt) {
        super(userid, passowrd,salt);
        
    }
    
}
