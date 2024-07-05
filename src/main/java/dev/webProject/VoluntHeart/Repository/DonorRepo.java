package dev.webProject.VoluntHeart.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import dev.webProject.VoluntHeart.Models.Users.DonorModel;

@Repository
public interface DonorRepo extends MongoRepository<DonorModel, String> {

    public DonorModel findByEmail(String email);

    public DonorModel findByGoogleId(String googleId);

}
