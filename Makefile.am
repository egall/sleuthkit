# File that we want to include in the dist
EXTRA_DIST = README_win32.txt README.txt INSTALL.txt ChangeLog.txt NEWS.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    m4/*.m4 \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/NOTES.txt \
    win32/*/*.vcxproj \
    win32/tsk-win.sln \
    win32/docs/* \
    bindings/java/README.txt \
    bindings/java/*.xml \
    bindings/java/doxygen/Doxyfile \
    bindings/java/doxygen/*.dox \
    bindings/java/doxygen/*.html \
    bindings/java/nbproject/project.xml \
    bindings/java/src/org/sleuthkit/datamodel/*.java \
    bindings/java/src/org/sleuthkit/datamodel/*.html \
    bindings/java/src/*.html \
    framework/*.txt \
    framework/Makefile.am \
    framework/bootstrap \
    framework/config/* \
    framework/config.h.in \
    framework/configure.ac \
    framework/m4/* \
    framework/tsk/framework/*.h \
    framework/tsk/framework/Makefile.am \
    framework/tsk/framework/extraction/Makefile.am \
    framework/tsk/framework/extraction/*.cpp \
    framework/tsk/framework/extraction/*.h \
    framework/tsk/framework/file/Makefile.am \
    framework/tsk/framework/file/*.cpp \
    framework/tsk/framework/file/*.h \
    framework/tsk/framework/pipeline/Makefile.am \
    framework/tsk/framework/pipeline/*.cpp \
    framework/tsk/framework/pipeline/*.h \
    framework/tsk/framework/services/Makefile.am \
    framework/tsk/framework/services/*.cpp \
    framework/tsk/framework/services/*.h \
    framework/tsk/framework/utilities/Makefile.am \
    framework/tsk/framework/utilities/*.cpp \
    framework/tsk/framework/utilities/*.h \
    framework/modules/* \
    framework/SampleConfig/*.xml \
    framework/docs/* \
    framework/man/* \
<<<<<<< HEAD
    framework/tools/tsk_analyzeimg/Makefile.am \
    framework/tools/tsk_analyzeimg/*.cpp \
    framework/tools/tsk_validatepipeline/Makefile.am \
    framework/tools/tsk_validatepipeline/*.cpp \
    framework/tools/Makefile.am \
    framework/msvcpp/*/*.vcxproj \
    framework/msvcpp/*/*.sln \
    framework/msvcpp/Makefile
||||||| merged common ancestors
    framework/tsk_analyzeimg/*.cpp \
    framework/tsk_validatepipeline/*.cpp \
    framework/win32/*/*.vcproj \
    framework/win32/*/*.sln \
    framework/win32/Makefile

CLEANFILES = tsk3/tsk_incs.h
=======
    framework/tsk_analyzeimg/*.cpp \
    framework/tsk_validatepipeline/*.cpp \
    framework/win32/*/*.vcproj \
    framework/win32/*/*.sln \
    framework/win32/Makefile

CLEANFILES = tsk/tsk_incs.h
>>>>>>> for_sleuthkit-xtafb2

ACLOCAL_AMFLAGS = -I m4

# directories to compile
if CPPUNIT
  UNIT_TESTS=unit_tests
endif

# Compile java bindings if all of the dependencies existed
if X_JNI
  JAVA_BINDINGS=bindings/java
else   
  JAVA_BINDINGS=
endif
<<<<<<< HEAD
||||||| merged common ancestors
SUBDIRS = tsk3 tools tests samples man $(UNIT_TESTS) $(JNI)
=======
SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JNI)
>>>>>>> for_sleuthkit-xtafb2

<<<<<<< HEAD
SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JAVA_BINDINGS) 

nobase_include_HEADERS = tsk/libtsk.h tsk/tsk_incs.h \
    tsk/base/tsk_base.h tsk/base/tsk_os.h \
    tsk/img/tsk_img.h tsk/vs/tsk_vs.h \
    tsk/vs/tsk_bsd.h tsk/vs/tsk_dos.h tsk/vs/tsk_gpt.h \
    tsk/vs/tsk_mac.h tsk/vs/tsk_sun.h \
    tsk/fs/tsk_fs.h tsk/fs/tsk_ffs.h tsk/fs/tsk_ext2fs.h tsk/fs/tsk_fatfs.h \
    tsk/fs/tsk_ntfs.h tsk/fs/tsk_iso9660.h tsk/fs/tsk_hfs.h tsk/fs/tsk_yaffs.h \
    tsk/hashdb/tsk_hashdb.h tsk/auto/tsk_auto.h
||||||| merged common ancestors
nobase_include_HEADERS = tsk3/libtsk.h tsk3/tsk_incs.h \
    tsk3/base/tsk_base.h tsk3/base/tsk_os.h \
    tsk3/img/tsk_img.h tsk3/vs/tsk_vs.h \
    tsk3/vs/tsk_bsd.h tsk3/vs/tsk_dos.h tsk3/vs/tsk_gpt.h \
    tsk3/vs/tsk_mac.h tsk3/vs/tsk_sun.h \
    tsk3/fs/tsk_fs.h tsk3/fs/tsk_ffs.h tsk3/fs/tsk_ext2fs.h tsk3/fs/tsk_fatfs.h \
    tsk3/fs/tsk_ntfs.h tsk3/fs/tsk_iso9660.h tsk3/fs/tsk_hfs.h \
    tsk3/hashdb/tsk_hashdb.h tsk3/auto/tsk_auto.h
=======
nobase_include_HEADERS = tsk/libtsk.h tsk/tsk_incs.h \
    tsk/base/tsk_base.h tsk/base/tsk_os.h \
    tsk/img/tsk_img.h tsk/vs/tsk_vs.h \
    tsk/vs/tsk_bsd.h tsk/vs/tsk_dos.h tsk/vs/tsk_gpt.h \
    tsk/vs/tsk_mac.h tsk/vs/tsk_sun.h \
    tsk/fs/tsk_fs.h tsk/fs/tsk_ffs.h tsk/fs/tsk_ext2fs.h tsk/fs/tsk_fatfs.h \
    tsk/fs/tsk_ntfs.h tsk/fs/tsk_iso9660.h tsk/fs/tsk_hfs.h tsk/fs/tsk_xtaffs.h \
    tsk/hashdb/tsk_hashdb.h tsk/auto/tsk_auto.h
>>>>>>> for_sleuthkit-xtafb2

nobase_dist_data_DATA = tsk/sorter/default.sort tsk/sorter/freebsd.sort \
    tsk/sorter/images.sort tsk/sorter/linux.sort tsk/sorter/openbsd.sort \
    tsk/sorter/solaris.sort tsk/sorter/windows.sort 

api-docs:
	doxygen tsk/docs/Doxyfile
	doxygen framework/docs/Doxyfile
	doxygen bindings/java/doxygen/Doxyfile

man-html:
	cd man;build-html
