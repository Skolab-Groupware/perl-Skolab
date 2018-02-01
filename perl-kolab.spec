##
##  perl-kolab.spec -- OpenPKG RPM Specification
##  Copyright (c) 2000-2004 The OpenPKG Project <http://www.openpkg.org/>
##  Copyright (c) 2000-2004 Ralf S. Engelschall <rse@engelschall.com>
##  Copyright (c) 2000-2004 Cable & Wireless <http://www.cw.com/>
##
##  Permission to use, copy, modify, and distribute this software for
##  any purpose with or without fee is hereby granted, provided that
##  the above copyright notice and this permission notice appear in all
##  copies.
##
##  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
##  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
##  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
##  IN NO EVENT SHALL THE AUTHORS AND COPYRIGHT HOLDERS AND THEIR
##  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
##  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
##  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
##  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
##  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
##  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
##  SUCH DAMAGE.
##

#   versions of individual parts


#   package information
Name:         perl-kolab
Summary:      Perl Modules for use with the Kolab server
URL:          http://www.kolab.org
Vendor:       Code Fusion, Klaraelvdalens Datakonsult AB
Packager:     Klaraelvdalens Datakonsult AB
Distribution: OpenPKG
Class:        PLUS
Group:        Language
License:      GPL/Artistic
Version:      5.8.7
Release:      20070420

#   list of sources
Source0:      perl-kolab-%{version}.tar.bz2

#   build information
Prefix:       %{l_prefix}
BuildRoot:    %{l_buildroot}
# BuildPreReq:  OpenPKG, openpkg >= 2.0, perl >= 5.8.7, perl-openpkg >= 5.8.7
BuildPreReq:  OpenPKG, openpkg >= 2.5.0
PreReq:       OpenPKG, openpkg >= 2.5.0, perl >= 5.8.7, perl-openpkg >= 5.8.7, perl-db, perl-mail, perl-ldap
AutoReq:      no
AutoReqProv:  no

%description
    Perl modules for use with the Kolab server

%prep

%setup -n %{name}-%{version}


%build
    # Notice: %{perl_sitearch} does not work,
    #   it picks up the host system's perl
#    %{configure} --prefix=%{l_prefix} \
#		 --includedir=%(eval "`%{l_prefix}/bin/perl -V:installsitearch`"; echo $installsitearch) \
#		 --dist=kolab
     %{configure} --prefix=%{l_prefix} --with-dist=kolab
    make

%install
    make DESTDIR=%{buildroot} install
    %{l_prefix}/bin/perl-openpkg -F perl-openpkg-files fixate cleanup
    %{l_rpmtool} files -v -ofiles -r$RPM_BUILD_ROOT %{l_files_std} `cat perl-openpkg-files`

%files -f files

%clean
    [ -d %{buildroot} -a "%{buildroot}" != "" ] && rm -rf  %{buildroot}

