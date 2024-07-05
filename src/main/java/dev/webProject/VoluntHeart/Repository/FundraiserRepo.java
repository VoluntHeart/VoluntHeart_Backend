package dev.webProject.VoluntHeart.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import dev.webProject.VoluntHeart.Models.Users.FundraiserModel;

@Repository
public interface FundraiserRepo extends MongoRepository<FundraiserModel, String> {

    public FundraiserModel findByEmail(String email);

    public FundraiserModel findByGoogleId(String googleId);

}
