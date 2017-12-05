package PasswordCrackerMaster;


import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class PasswordDecrypterJob {
    // if you want to know CompletableFuture class,
    // refer to the site; https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/CompletableFuture.html
    
    CompletableFuture<String> passwordFuture = new CompletableFuture<>();
    
    /**
     * get()
     * Waits if necessary for this future to complete, and then
     * returns its result.
     *
     * @return the result value
     * @throws ExecutionException 
     * @throws InterruptedException 
     */
    public String getPassword() throws InterruptedException, ExecutionException {
        /** COMPLETE **/
    	return passwordFuture.get();
    }
    
    /**
     * complete(T value)
     * If not already completed, sets the value returned by get() and related methods to the given value.
     * param : value the result value
     *
     * @return {@code true} if this invocation caused this CompletableFuture
     * to transition to a completed state, else {@code false}
     */
    public boolean setPassword(String password) { // IMPORTANT: changed void to true
        /** COMPLETE **/
    	return passwordFuture.complete(password);
    }
    
}



