Buffered FUSE
======================

* Maintainer : Sooman Jeong (smartzzz77@gmail.com)
* Contributor : 
* Base source code : https://github.com/android/platform_system_core/blob/kitkat-release/sdcard/sdcard.c 

### Reference: 
 * Sooman Jeong, Youjip Won, "Buffered FUSE: optimising the Android IO stack for user-level filesystem" , International Journal of Embedded Systems (IJES), Special Issue for Embedded and Ubiquitous Computing, 2014 Vol. 6, No.2/3, pp.95 - 107, doi:10.1504/IJES.2014.063806

### Acknowledgement:
 * This work is supported by IT R&D program MKE/KEIT (No. 10041608, Embedded System Software for New-memory based Smart Device). 

Android imposes user-level filesystem (FUSE) over native filesystem partition to provide flexibility in managing the internal storage space and to maintain host	compatibility. However, the overhead of user-level filesystem is prohibitively large and the native storage bandwidth is significantly under-utilized. In order to address this overhead of user-level filesystem, we propose Buffered FUSE (bFUSE). The key technical ingredients of Buffered FUSE are (i) extended FUSE IO size, (ii) internal user-level write buffer (FUSE buffer) and (iii) independent management thread which performs time driven FUSE buffer synchronization.                                                       			


