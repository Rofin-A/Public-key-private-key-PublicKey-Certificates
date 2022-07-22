/**
 * @classname: SensorLoc.Java
 * @author: Rofin A
 */
/*----------------------------------------------------------------------------- 
*  Purpose: This class will be used by InstallerServer.Java to hold the state of
   server locations
-------------------------------------------------------------------------------*/
package PublicKeyCertificates;

// This class is create to hold the instances of installed sensors
public class SensorLoc {
    String user;
    String latitude;
    String longitude;
    String altitude;
    
    SensorLoc(String user,String latitude,String longitude,String altitude){
        this.user = user;
        this.latitude = latitude;
        this.longitude = longitude;
        this.altitude = altitude;
    }
}
