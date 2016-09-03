themedir = $(datadir)/plymouth/themes/ubuntu-logo
nodist_theme_DATA = ubuntu-logo.plymouth ubuntu-logo-scale-2.plymouth
dist_theme_DATA =   ubuntu-logo.script                                \
                    ubuntu-logo-scale-2.script                        \
                    ubuntu-logo.grub                                  \
                    ubuntu-logo.png                                   \
                    ubuntu-logo16.png                                 \
                    password-field.png                                \
                    password-field16.png                              \
                    progress-dot-off.png                              \
                    progress-dot-off16.png                            \
                    progress-dot-on.png                               \
                    progress-dot-on16.png



MAINTAINERCLEANFILES = Makefile.in ubuntu-logo.plymouth ubuntu-logo-scale-2.plymouth ubuntu-logo.script ubuntu-logo-scale-2.script
CLEANFILES = ubuntu-logo.plymouth ubuntu-logo-scale-2.plymouth ubuntu-logo.script ubuntu-logo-scale-2.script

ubuntu-logo.plymouth: $(srcdir)/ubuntu-logo.plymouth.in
	sed -e 's,[@]PLYMOUTH_THEME_PATH[@],$(PLYMOUTH_THEME_PATH),g;s,[@]EXTRA_NAME[@],,g;s,[@]SCRIPT_NAME[@],ubuntu-logo,g' \
	       $(srcdir)/ubuntu-logo.plymouth.in > ubuntu-logo.plymouth

ubuntu-logo-scale-2.plymouth: $(srcdir)/ubuntu-logo.plymouth.in
	sed -e 's,[@]PLYMOUTH_THEME_PATH[@],$(PLYMOUTH_THEME_PATH),g;s,[@]EXTRA_NAME[@],(Scale x2),g;s,[@]SCRIPT_NAME[@],ubuntu-logo-scale-2,g' \
	       $(srcdir)/ubuntu-logo.plymouth.in > ubuntu-logo-scale-2.plymouth

ubuntu-logo.script: $(srcdir)/ubuntu-logo.script.in
	sed -e 's,[@]SCALEFACTOR[@],1,g' \
	       $(srcdir)/ubuntu-logo.script.in > ubuntu-logo.script

ubuntu-logo-scale-2.script: $(srcdir)/ubuntu-logo.script.in
	sed -e 's,[@]SCALEFACTOR[@],2,g' \
	       $(srcdir)/ubuntu-logo.script.in > ubuntu-logo-scale-2.script

EXTRA_DIST = ubuntu-logo.plymouth.in ubuntu-logo.script.in
