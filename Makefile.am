# File that we want to include in the dist
EXTRA_DIST = README_win32.txt README.txt INSTALL.txt ChangeLog.txt NEWS.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    m4/*.m4 \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/NOTES.txt \
    win32/*/*.vcproj \
    win32/tsk-win.sln \
    win32/docs/* \
    bindings/java/README.txt \
    bindings/java/*.xml \
    bindings/java/doxygen/* \
    bindings/java/nbproject/project.xml \
    bindings/java/src/org/sleuthkit/datamodel/*.java \
    bindings/java/src/org/sleuthkit/datamodel/*.html \
    bindings/java/src/*.html \
    bindings/java/test \
    bindings/java/teststandards \
    framework/*.txt \
    framework/*.h \
    framework/Extraction/*.cpp \
    framework/Extraction/*.h \
    framework/File/*.cpp \
    framework/File/*.h \
    framework/Pipeline/*.cpp \
    framework/Pipeline/*.h \
    framework/SampleConfig/*.xml \
    framework/Services/*.cpp \
    framework/Services/*.h \
    framework/TskModules/* \
    framework/Utilities/*.cpp \
    framework/Utilities/*.h \
    framework/docs/* \
    framework/man/* \
    framework/tsk_analyzeimg/*.cpp \
    framework/tsk_validatepipeline/*.cpp \
    framework/win32/*/*.vcproj \
    framework/win32/*/*.sln \
    framework/win32/Makefile

CLEANFILES = tsk/tsk_incs.h

ACLOCAL_AMFLAGS = -I m4

# directories to compile
if CPPUNIT
  UNIT_TESTS=unit_tests
endif
if X_JNI
  JNI=bindings/java/jni
endif
SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JNI)

nobase_include_HEADERS = tsk/libtsk.h tsk/tsk_incs.h \
    tsk/base/tsk_base.h tsk/base/tsk_os.h \
    tsk/img/tsk_img.h tsk/vs/tsk_vs.h \
    tsk/vs/tsk_bsd.h tsk/vs/tsk_dos.h tsk/vs/tsk_gpt.h \
    tsk/vs/tsk_mac.h tsk/vs/tsk_sun.h \
    tsk/fs/tsk_fs.h tsk/fs/tsk_ffs.h tsk/fs/tsk_ext2fs.h tsk/fs/tsk_fatfs.h \
    tsk/fs/tsk_ntfs.h tsk/fs/tsk_iso9660.h tsk/fs/tsk_hfs.h tsk/fs/tsk_xtaffs.h \
    tsk/hashdb/tsk_hashdb.h tsk/auto/tsk_auto.h

nobase_dist_data_DATA = tsk/sorter/default.sort tsk/sorter/freebsd.sort \
    tsk/sorter/images.sort tsk/sorter/linux.sort tsk/sorter/openbsd.sort \
    tsk/sorter/solaris.sort tsk/sorter/windows.sort 

api-docs:
	doxygen tsk/docs/Doxyfile
	doxygen framework/docs/Doxyfile
	doxygen bindings/java/doxygen/Doxyfile

man-html:
	cd man;build-html
