/**
 * @classname: ChiefSensorInstaller.Java
 * @author: Rofin A
 */
/*----------------------------------------------------------------------------- 
*  Purpose: This class is created to intantiate Chief Sensor installers
*  in the InstallerServer.Java Class. Based on the instance, installers 
*  authorization for relocating the sensor will be assesed
-------------------------------------------------------------------------------*/
package PublicKeyCertificates;

/**
 *
 * @author rofin
 */
//This class is create to hold instances of chiefSensor installers
public class ChiefSensorInstaller extends SensorInstaller{
// --------------------------Constructor------------------------
    public ChiefSensorInstaller(String userid, String passowrd,String salt) {
        super(userid, passowrd,salt);
    }
}
