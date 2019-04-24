package org.p4.p4d2.tutorial.cli;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.console.CommandLine;
import org.apache.karaf.shell.api.console.Completer;
import org.apache.karaf.shell.api.console.Session;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.onosproject.cli.AbstractShellCommand;
import org.p4.p4d2.tutorial.Srv6App;

import java.util.List;

/**
 * FIXME completer for SIDs based on device config.
 */
@Service
public class Srv6SidCompleter implements Completer {


    @Override
    public int complete(Session session, CommandLine commandLine, List<String> candidates) {
        // Delegate string completer
        StringsCompleter delegate = new StringsCompleter();
        Srv6App srv6App = AbstractShellCommand.get(Srv6App.class);
//        Iterator<Ip4Address> it = dhcpService.getAvailableIPs().iterator();
//        SortedSet<String> strings = delegate.getStrings();
//
//        while (it.hasNext()) {
//            strings.add(it.next().toString());
//        }

        // Now let the completer do the work for figuring out what to offer.
        return delegate.complete(session, commandLine, candidates);
    }
}
